package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/spf13/viper"
)

func writeWhitelist(t *testing.T, input string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hosts.yaml")
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func gatheredHostTuples(t *testing.T, collector prometheus.Collector, labels []string) map[string]struct{} {
	t.Helper()
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(collector); err != nil {
		t.Fatal(err)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]struct{})
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			values := make([]string, len(labels))
			for i, name := range labels {
				for _, label := range metric.GetLabel() {
					if label.GetName() == name {
						values[i] = label.GetValue()
						break
					}
				}
			}
			key, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			got[string(key)] = struct{}{}
		}
	}
	return got
}

func TestReadHostWhitelist(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "yaml", input: "hosts:\n  - www.example.com\n  - api.example.com\n", want: []string{"www.example.com", "api.example.com"}},
		{name: "json", input: `{"hosts":["www.example.com","api.example.com"]}`, want: []string{"www.example.com", "api.example.com"}},
		{name: "empty valid list", input: "hosts: []\n", want: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, category, err := readHostWhitelist(writeWhitelist(t, tt.input))
			if err != nil || category != "" {
				t.Fatalf("readHostWhitelist() error = %v, category = %q", err, category)
			}
			if len(got.allowed) != len(tt.want) {
				t.Fatalf("got %d hosts, want %d", len(got.allowed), len(tt.want))
			}
			for _, host := range tt.want {
				if _, ok := got.allowed[host]; !ok {
					t.Errorf("host %q not allowed", host)
				}
			}
			if !got.enabled {
				t.Error("valid file must enable filtering")
			}
		})
	}
}

func TestReadHostWhitelistRejectsInvalidDocuments(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		category string
	}{
		{name: "duplicate key", input: "hosts: [www.example.com]\nhosts: [api.example.com]", category: "invalid schema"},
		{name: "scalar", input: "42", category: "invalid schema"},
		{name: "null", input: "null", category: "invalid schema"},
		{name: "merge key", input: "base: &base {hosts: [www.example.com]}\n<<: *base", category: "invalid schema"},
		{name: "multiple documents", input: "hosts: [www.example.com]\n---\nhosts: [api.example.com]", category: "malformed"},
		{name: "additional key", input: "hosts: [www.example.com]\nother: value", category: "invalid schema"},
		{name: "non-list hosts", input: "hosts: www.example.com", category: "invalid schema"},
		{name: "non-string entry", input: "hosts: [www.example.com, 42]", category: "invalid schema"},
		{name: "null entry", input: "hosts: [null]", category: "invalid schema"},
		{name: "empty", input: "", category: "empty"},
		{name: "malformed", input: "hosts: [", category: "malformed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, category, err := readHostWhitelist(writeWhitelist(t, tt.input))
			if err == nil || category != tt.category {
				t.Fatalf("readHostWhitelist() error = %v, category = %q, want %q", err, category, tt.category)
			}
		})
	}
}

func TestLoadHostWhitelistRetainsPreviousSnapshot(t *testing.T) {
	path := writeWhitelist(t, "hosts: [good.example.com]")
	previous := loadHostWhitelist(path, emptyHostWhitelist())
	if _, ok := previous.allowed["good.example.com"]; !previous.enabled || !ok {
		t.Fatalf("initial load = %#v", previous)
	}

	for _, input := range []string{"", "hosts: [", "hosts: www.example.com", "hosts: [bad.example.com]\nother: value"} {
		if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
			t.Fatal(err)
		}
		got := loadHostWhitelist(path, previous)
		if _, ok := got.allowed["good.example.com"]; !got.enabled || !ok || len(got.allowed) != 1 {
			t.Fatalf("input %q changed snapshot to %#v", input, got)
		}
	}
}

func TestLoadHostWhitelistReplacesValidSnapshot(t *testing.T) {
	path := writeWhitelist(t, "hosts: [good.example.com]")
	previous := loadHostWhitelist(path, emptyHostWhitelist())
	if err := os.WriteFile(path, []byte("hosts: [replacement.example.com]"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := loadHostWhitelist(path, previous)
	if !got.enabled || !got.Allows("replacement.example.com") || got.Allows("good.example.com") {
		t.Fatalf("replacement snapshot = %#v", got)
	}
}

func TestLoadHostWhitelistRetainsValidSnapshotWhenFileBecomesUnreadable(t *testing.T) {
	path := writeWhitelist(t, "hosts: [good.example.com]")
	previous := loadHostWhitelist(path, emptyHostWhitelist())
	if err := os.WriteFile(path, []byte("hosts: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	got := loadHostWhitelist(path, previous)
	if !sameHostWhitelist(got, previous) {
		t.Fatalf("malformed file changed snapshot to %#v", got)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	got = loadHostWhitelist(path, previous)
	if !sameHostWhitelist(got, previous) || !got.enabled || !got.Allows("good.example.com") || got.Allows("bad.example.com") {
		t.Fatalf("unreadable file changed snapshot to %#v", got)
	}
}

func TestLoadHostWhitelistDisabledStates(t *testing.T) {
	if got := loadHostWhitelist("", emptyHostWhitelist()); got.enabled || !got.Allows("arbitrary.example.com") {
		t.Fatalf("empty path = %#v", got)
	}
	if got := loadHostWhitelist(filepath.Join(t.TempDir(), "missing"), emptyHostWhitelist()); got.enabled || !got.Allows("arbitrary.example.com") {
		t.Fatalf("missing initial path = %#v", got)
	}
}

func TestLoadHostWhitelistEmptyListRetainsScrapeAll(t *testing.T) {
	path := writeWhitelist(t, "hosts: []")
	previous := loadHostWhitelist(path, emptyHostWhitelist())
	if !previous.enabled || len(previous.allowed) != 0 || !previous.Allows("anything.example.com") {
		t.Fatalf("empty valid snapshot = %#v", previous)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	got := loadHostWhitelist(path, previous)
	if !sameHostWhitelist(got, previous) || !got.Allows("anything.example.com") {
		t.Fatalf("retained empty snapshot = %#v", got)
	}
}

func TestHostWhitelistAllowsExactMatches(t *testing.T) {
	path := writeWhitelist(t, "hosts: [www.example.com]")
	whitelist, _, err := readHostWhitelist(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"WWW.EXAMPLE.COM", "example.com", "www.example.com.evil", "evilwww.example.com", "*.example.com", " www.example.com", "www.example.com ", "unrelated.example.com"} {
		if whitelist.Allows(host) {
			t.Errorf("Allows(%q) = true", host)
		}
	}
	if !whitelist.Allows("www.example.com") {
		t.Error("exact host was rejected")
	}
	if !emptyHostWhitelist().Allows("anything.example.com") {
		t.Error("disabled whitelist filtered a host")
	}
	if got, _, err := readHostWhitelist(writeWhitelist(t, "hosts: []")); err != nil || !got.Allows("anything.example.com") {
		t.Error("enabled empty whitelist did not allow all hosts")
	}
}

func TestHostWhitelistSnapshotIsShared(t *testing.T) {
	snapshot := hostWhitelist{enabled: true, allowed: map[string]struct{}{"good.example.com": {}}}
	start := make(chan struct{})
	results := make(chan bool, 4)
	for i := 0; i < 4; i++ {
		go func() {
			<-start
			results <- snapshot.Allows("good.example.com") && !snapshot.Allows("bad.example.com")
		}()
	}
	close(start)
	for i := 0; i < 4; i++ {
		if !<-results {
			t.Fatal("collector did not observe the same snapshot")
		}
	}
}

func TestHostSeriesRegistryReconcilesRemovedTuples(t *testing.T) {
	registry := newHostSeriesRegistry()
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_host_counter"}, []string{"host", "kind"})
	registry.Register(counter, "host", "kind")
	for _, kind := range []string{"kept", "stale"} {
		counter.WithLabelValues("host.example.com", kind).Add(1)
		registry.Observe(counter, prometheus.Labels{"host": "host.example.com", "kind": kind})
	}
	registry.Reconcile()
	registry.ResetScrape()
	counter.WithLabelValues("host.example.com", "kept").Add(1)
	registry.Observe(counter, prometheus.Labels{"host": "host.example.com", "kind": "kept"})
	registry.Reconcile()
	if got := gatheredHostTuples(t, counter, []string{"host", "kind"}); len(got) != 1 {
		t.Fatalf("gathered tuples = %#v", got)
	}
	if counter.DeleteLabelValues("host.example.com", "stale") {
		t.Fatal("stale tuple was not deleted")
	}
}

func TestHostSeriesRegistryReconcilesCounterAndGaugeWithDifferentLabelOrders(t *testing.T) {
	registry := newHostSeriesRegistry()
	counter := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_tuple_counter"}, []string{"host", "kind"})
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_tuple_gauge"}, []string{"kind", "host"})
	registry.Register(counter, "host", "kind")
	registry.Register(gauge, "kind", "host")
	counter.WithLabelValues("stale.example.com", "counter").Add(1)
	registry.Observe(counter, prometheus.Labels{"host": "stale.example.com", "kind": "counter"})
	gauge.WithLabelValues("gauge", "stale.example.com").Set(1)
	registry.Observe(gauge, prometheus.Labels{"kind": "gauge", "host": "stale.example.com"})
	registry.Reconcile()
	registry.ResetScrape()
	registry.Reconcile()
	if len(gatheredHostTuples(t, counter, []string{"host", "kind"})) != 0 || len(gatheredHostTuples(t, gauge, []string{"kind", "host"})) != 0 {
		t.Fatal("stale series was not removed")
	}
}

func TestHostSeriesRegistryResetKeepsFamiliesAndBoundsBookkeeping(t *testing.T) {
	registry := newHostSeriesRegistry()
	vector := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_reset_host_counter"}, []string{"host"})
	registry.Register(vector, "host")

	vector.WithLabelValues("first.example.com").Add(1)
	registry.Observe(vector, prometheus.Labels{"host": "first.example.com"})
	registry.Reconcile()
	registry.ResetScrape()
	if len(registry.families) != 1 || len(registry.families[0].emitted) != 1 || len(registry.families[0].observed) != 0 {
		t.Fatalf("reset bookkeeping = %#v", registry.families)
	}
	registry.Reconcile()
	if len(gatheredHostTuples(t, vector, []string{"host"})) != 0 {
		t.Fatal("series was deleted from scrape-all whitelist")
	}
}

func TestFetchMetricsReconcilesZeroZoneAndErrorScrapes(t *testing.T) {
	previousRegistry := hostSeriesRegistryState
	previousSnapshot := hostWhitelistSnapshot
	previousPath := viper.GetString("host_whitelist_path")
	t.Cleanup(func() {
		hostSeriesRegistryState = previousRegistry
		hostWhitelistSnapshot = previousSnapshot
		viper.Set("host_whitelist_path", previousPath)
	})

	vector := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_orchestration_host_gauge"}, []string{"zone", "host", "status"})
	hostSeriesRegistryState = newHostSeriesRegistry()
	hostSeriesRegistryState.Register(vector, "zone", "host", "status")
	viper.Set("host_whitelist_path", "")

	labels := prometheus.Labels{"zone": "zone-a", "host": "stale.example.com", "status": "200"}
	vector.With(labels).Set(1)
	hostSeriesRegistryState.Observe(vector, labels)
	hostSeriesRegistryState.Reconcile()

	fetchMetricsWithRunner(func(hostWhitelist, *sync.WaitGroup) {})
	if got := gatheredHostTuples(t, vector, []string{"zone", "host", "status"}); len(got) != 0 {
		t.Fatalf("zero-zone scrape retained tuples = %#v", got)
	}

	vector.With(labels).Set(1)
	hostSeriesRegistryState.Observe(vector, labels)
	hostSeriesRegistryState.Reconcile()
	fetchMetricsWithRunner(func(_ hostWhitelist, wg *sync.WaitGroup) {
		wg.Add(1)
		go func() { defer wg.Done() }()
	})
	if got := gatheredHostTuples(t, vector, []string{"zone", "host", "status"}); len(got) != 0 {
		t.Fatalf("error scrape retained tuples = %#v", got)
	}
}

func TestHostMetricFilteringBoundaries(t *testing.T) {
	allowed := hostWhitelist{enabled: true, allowed: map[string]struct{}{"good.example.com": {}}}
	registry := newHostSeriesRegistry()
	registry.Register(zoneRequestOriginStatusCountryHost, "zone", "account", "status", "country", "host")
	registry.Register(zoneRequestStatusCountryHost, "zone", "account", "status", "country", "host")
	registry.Register(zoneFirewallEventsCount, "zone", "account", "action", "source", "rule", "host", "country")
	registry.Register(zoneColocationVisits, "zone", "account", "colocation", "host")
	registry.Register(zoneColocationEdgeResponseBytes, "zone", "account", "colocation", "host")
	registry.Register(zoneColocationRequestsTotal, "zone", "account", "colocation", "host")
	registry.Register(zoneEdgeErrorsByPath, "zone", "account", "status", "host", "path")

	zone := zoneResp{}
	if err := json.Unmarshal([]byte(`{"httpRequestsAdaptiveGroups":[{"count":1,"dimensions":{"originResponseStatus":200,"clientCountryName":"US","clientRequestHTTPHost":"good.example.com"}},{"count":1,"dimensions":{"originResponseStatus":200,"clientCountryName":"US","clientRequestHTTPHost":"bad.example.com"}}],"httpRequestsEdgeCountryHost":[{"count":1,"dimensions":{"edgeResponseStatus":200,"clientCountryName":"US","clientRequestHTTPHost":"good.example.com"}},{"count":1,"dimensions":{"edgeResponseStatus":200,"clientCountryName":"US","clientRequestHTTPHost":"bad.example.com"}}],"firewallEventsAdaptiveGroups":[{"count":1,"dimensions":{"action":"block","source":"waf","ruleId":"rule","clientCountryName":"US","clientRequestHTTPHost":"good.example.com"}},{"count":1,"dimensions":{"action":"block","source":"waf","ruleId":"rule","clientCountryName":"US","clientRequestHTTPHost":"bad.example.com"}}]}`), &zone); err != nil {
		t.Fatal(err)
	}
	addHTTPAdaptiveGroups(&zone, "zone", "account", allowed, registry)
	addFirewallGroupsWithRules(&zone, "zone", "account", allowed, registry, map[string]string{"rule": "rule"})

	colo := zoneRespColo{}
	if err := json.Unmarshal([]byte(`{"httpRequestsAdaptiveGroups":[{"count":1,"dimensions":{"coloCode":"AMS","clientRequestHTTPHost":"good.example.com"}},{"count":1,"dimensions":{"coloCode":"AMS","clientRequestHTTPHost":"bad.example.com"}}]}`), &colo); err != nil {
		t.Fatal(err)
	}
	for _, c := range colo.ColoGroups {
		addColocationGroup(c, "zone", "account", allowed, registry)
	}

	edges := zoneRespEdgeErrorsByPath{}
	if err := json.Unmarshal([]byte(`{"httpRequestsAdaptiveGroups":[{"count":1,"dimensions":{"edgeResponseStatus":500,"clientRequestHTTPHost":"good.example.com","clientRequestPath":"/users/1"}},{"count":1,"dimensions":{"edgeResponseStatus":500,"clientRequestHTTPHost":"bad.example.com","clientRequestPath":"/users/2"}}]}`), &edges); err != nil {
		t.Fatal(err)
	}
	addEdgeErrorsByPath(&edges, "zone", "account", allowed, registry)

	registry.mu.Lock()
	defer registry.mu.Unlock()
	for _, family := range registry.families {
		if len(family.observed) != 1 {
			t.Errorf("observed hosts = %#v", family.observed)
		}
		if _, ok := family.observed["good.example.com"]; !ok {
			t.Errorf("allowed host missing: %#v", family.observed)
		}
	}

	nonHost := zoneResp{}
	if err := json.Unmarshal([]byte(`{"httpRequests1mGroups":[{"sum":{"requests":7}}]}`), &nonHost); err != nil {
		t.Fatal(err)
	}
	addHTTPGroups(&nonHost, "non-host-zone", "account")
	if got := testutil.ToFloat64(zoneRequestTotal.WithLabelValues("non-host-zone", "account")); got != 7 {
		t.Fatalf("non-host request total = %v", got)
	}
}

func task3Registry() *hostSeriesRegistry {
	registry := newHostSeriesRegistry()
	registry.Register(zoneRequestOriginStatusCountryHost, "zone", "account", "status", "country", "host")
	registry.Register(zoneRequestOriginStatusCountryHostP50, "zone", "account", "status", "country", "host")
	registry.Register(zoneRequestOriginStatusCountryHostP95, "zone", "account", "status", "country", "host")
	registry.Register(zoneRequestOriginStatusCountryHostP99, "zone", "account", "status", "country", "host")
	registry.Register(zoneRequestStatusCountryHost, "zone", "account", "status", "country", "host")
	registry.Register(zoneColocationVisits, "zone", "account", "colocation", "host")
	registry.Register(zoneColocationEdgeResponseBytes, "zone", "account", "colocation", "host")
	registry.Register(zoneColocationRequestsTotal, "zone", "account", "colocation", "host")
	registry.Register(zoneFirewallEventsCount, "zone", "account", "action", "source", "rule", "host", "country")
	registry.Register(zoneEdgeErrorsByPath, "zone", "account", "status", "host", "path")
	return registry
}

func populateTask3Families(t *testing.T, zone string, snapshot hostWhitelist, registry *hostSeriesRegistry) {
	t.Helper()
	const hosts = `{"count":%d,"dimensions":{"originResponseStatus":200,"clientCountryName":"US","clientRequestHTTPHost":"%s"},"quantiles":{"originResponseDurationMsP50":101,"originResponseDurationMsP95":202,"originResponseDurationMsP99":303}}`
	var zoneData zoneResp
	if err := json.Unmarshal([]byte(fmt.Sprintf(`{"httpRequestsAdaptiveGroups":[`+hosts+`,`+hosts+`],"httpRequestsEdgeCountryHost":[{"count":12,"dimensions":{"edgeResponseStatus":200,"clientCountryName":"US","clientRequestHTTPHost":"good.example.com"}},{"count":12,"dimensions":{"edgeResponseStatus":200,"clientCountryName":"US","clientRequestHTTPHost":"bad.example.com"}}],"firewallEventsAdaptiveGroups":[{"count":13,"dimensions":{"action":"block","source":"waf","ruleId":"rule-1","clientCountryName":"US","clientRequestHTTPHost":"good.example.com"}},{"count":13,"dimensions":{"action":"block","source":"waf","ruleId":"rule-1","clientCountryName":"US","clientRequestHTTPHost":"bad.example.com"}}]}`, 11, "good.example.com", 11, "bad.example.com")), &zoneData); err != nil {
		t.Fatal(err)
	}
	addHTTPAdaptiveGroups(&zoneData, zone, "account", snapshot, registry)
	addFirewallGroupsWithRules(&zoneData, zone, "account", snapshot, registry, map[string]string{"rule-1": "rule-1"})

	var colo zoneRespColo
	if err := json.Unmarshal([]byte(`{"httpRequestsAdaptiveGroups":[{"count":14,"sum":{"visits":15,"edgeResponseBytes":16},"dimensions":{"coloCode":"AMS","clientRequestHTTPHost":"good.example.com"}},{"count":14,"sum":{"visits":15,"edgeResponseBytes":16},"dimensions":{"coloCode":"AMS","clientRequestHTTPHost":"bad.example.com"}}]}`), &colo); err != nil {
		t.Fatal(err)
	}
	for _, group := range colo.ColoGroups {
		addColocationGroup(group, zone, "account", snapshot, registry)
	}

	var edges zoneRespEdgeErrorsByPath
	if err := json.Unmarshal([]byte(`{"httpRequestsAdaptiveGroups":[{"count":17,"dimensions":{"edgeResponseStatus":500,"clientRequestHTTPHost":"good.example.com","clientRequestPath":"/users/1"}},{"count":17,"dimensions":{"edgeResponseStatus":500,"clientRequestHTTPHost":"bad.example.com","clientRequestPath":"/users/2"}}]}`), &edges); err != nil {
		t.Fatal(err)
	}
	addEdgeErrorsByPath(&edges, zone, "account", snapshot, registry)
}

func resetTask3Metrics(zone string) {
	label := prometheus.Labels{"zone": zone}
	zoneRequestOriginStatusCountryHost.DeletePartialMatch(label)
	zoneRequestOriginStatusCountryHostP50.DeletePartialMatch(label)
	zoneRequestOriginStatusCountryHostP95.DeletePartialMatch(label)
	zoneRequestOriginStatusCountryHostP99.DeletePartialMatch(label)
	zoneRequestStatusCountryHost.DeletePartialMatch(label)
	zoneColocationVisits.DeletePartialMatch(label)
	zoneColocationEdgeResponseBytes.DeletePartialMatch(label)
	zoneColocationRequestsTotal.DeletePartialMatch(label)
	zoneFirewallEventsCount.DeletePartialMatch(label)
	zoneEdgeErrorsByPath.DeletePartialMatch(label)
}

func assertTask3Family(t *testing.T, collector prometheus.Collector, labels []string, hosts []string, tuple func(string) []string) {
	t.Helper()
	all := gatheredHostTuples(t, collector, labels)
	zone := tuple(hosts[0])[0]
	got := make(map[string]struct{})
	for key := range all {
		var values []string
		if err := json.Unmarshal([]byte(key), &values); err != nil {
			t.Fatal(err)
		}
		if len(values) > 0 && values[0] == zone {
			got[key] = struct{}{}
		}
	}
	want := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		want[string(mustJSON(tuple(host)))] = struct{}{}
	}
	if len(got) != len(want) {
		t.Fatalf("gathered tuples = %#v, want %d tuples: %#v", got, len(want), want)
	}
	for key := range want {
		if _, ok := got[key]; !ok {
			t.Errorf("gathered tuples = %#v, missing %s", got, key)
		}
	}
}

func TestAllRegisteredHostMetricFamilies(t *testing.T) {
	for _, tt := range []struct {
		name     string
		zone     string
		snapshot hostWhitelist
		want     int
	}{
		{name: "empty whitelist disabled", zone: "task3-disabled", snapshot: emptyHostWhitelist(), want: 2},
		{name: "empty whitelist enabled", zone: "task3-empty", snapshot: hostWhitelist{enabled: true, allowed: map[string]struct{}{}}, want: 2},
		{name: "one host", zone: "task3-one", snapshot: hostWhitelist{enabled: true, allowed: map[string]struct{}{"good.example.com": {}}}, want: 1},
		{name: "both hosts", zone: "task3-both", snapshot: hostWhitelist{enabled: true, allowed: map[string]struct{}{"good.example.com": {}, "bad.example.com": {}}}, want: 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, zone := range []string{"task3-disabled", "task3-empty", "task3-one", "task3-both"} {
				resetTask3Metrics(zone)
			}
			registry := task3Registry()
			populateTask3Families(t, tt.zone, tt.snapshot, registry)
			registry.Reconcile()
			wantHosts := []string{"good.example.com"}
			if tt.want == 2 {
				wantHosts = append(wantHosts, "bad.example.com")
			}
			assertTask3Family(t, zoneRequestOriginStatusCountryHost, []string{"zone", "account", "status", "country", "host"}, wantHosts, func(host string) []string { return []string{tt.zone, "account", "200", "US", host} })
			assertTask3Family(t, zoneRequestOriginStatusCountryHostP50, []string{"zone", "account", "status", "country", "host"}, wantHosts, func(host string) []string { return []string{tt.zone, "account", "200", "US", host} })
			assertTask3Family(t, zoneRequestOriginStatusCountryHostP95, []string{"zone", "account", "status", "country", "host"}, wantHosts, func(host string) []string { return []string{tt.zone, "account", "200", "US", host} })
			assertTask3Family(t, zoneRequestOriginStatusCountryHostP99, []string{"zone", "account", "status", "country", "host"}, wantHosts, func(host string) []string { return []string{tt.zone, "account", "200", "US", host} })
			assertTask3Family(t, zoneRequestStatusCountryHost, []string{"zone", "account", "status", "country", "host"}, wantHosts, func(host string) []string { return []string{tt.zone, "account", "200", "US", host} })
			assertTask3Family(t, zoneColocationVisits, []string{"zone", "account", "colocation", "host"}, wantHosts, func(host string) []string { return []string{tt.zone, "account", "AMS", host} })
			assertTask3Family(t, zoneColocationEdgeResponseBytes, []string{"zone", "account", "colocation", "host"}, wantHosts, func(host string) []string { return []string{tt.zone, "account", "AMS", host} })
			assertTask3Family(t, zoneColocationRequestsTotal, []string{"zone", "account", "colocation", "host"}, wantHosts, func(host string) []string { return []string{tt.zone, "account", "AMS", host} })
			assertTask3Family(t, zoneFirewallEventsCount, []string{"zone", "account", "action", "source", "rule", "host", "country"}, wantHosts, func(host string) []string { return []string{tt.zone, "account", "block", "waf", "rule-1", host, "US"} })
			assertTask3Family(t, zoneEdgeErrorsByPath, []string{"zone", "account", "status", "host", "path"}, wantHosts, func(host string) []string { return []string{tt.zone, "account", "500", host, "/users/:id"} })

			if tt.want == 1 {
				labels := prometheus.Labels{"zone": tt.zone, "account": "account", "status": "200", "country": "US", "host": "good.example.com"}
				for _, metric := range []struct {
					name string
					got  float64
					want float64
				}{
					{zoneRequestOriginStatusCountryHostMetricName.String(), testutil.ToFloat64(zoneRequestOriginStatusCountryHost.With(labels)), 11},
					{zoneRequestOriginStatusCountryHostP50MetricName.String(), testutil.ToFloat64(zoneRequestOriginStatusCountryHostP50.With(labels)), 101},
					{zoneRequestOriginStatusCountryHostP95MetricName.String(), testutil.ToFloat64(zoneRequestOriginStatusCountryHostP95.With(labels)), 202},
					{zoneRequestOriginStatusCountryHostP99MetricName.String(), testutil.ToFloat64(zoneRequestOriginStatusCountryHostP99.With(labels)), 303},
					{zoneRequestStatusCountryHostMetricName.String(), testutil.ToFloat64(zoneRequestStatusCountryHost.With(labels)), 12},
				} {
					if metric.got != metric.want {
						t.Errorf("%s = %v, want %v", metric.name, metric.got, metric.want)
					}
				}
				coloLabels := prometheus.Labels{"zone": tt.zone, "account": "account", "colocation": "AMS", "host": "good.example.com"}
				for _, metric := range []struct {
					name string
					got  float64
					want float64
				}{
					{zoneColocationRequestsTotalMetricName.String(), testutil.ToFloat64(zoneColocationRequestsTotal.With(coloLabels)), 14},
					{zoneColocationVisitsMetricName.String(), testutil.ToFloat64(zoneColocationVisits.With(coloLabels)), 15},
					{zoneColocationEdgeResponseBytesMetricName.String(), testutil.ToFloat64(zoneColocationEdgeResponseBytes.With(coloLabels)), 16},
				} {
					if metric.got != metric.want {
						t.Errorf("%s = %v, want %v", metric.name, metric.got, metric.want)
					}
				}
				firewallLabels := prometheus.Labels{"zone": tt.zone, "account": "account", "action": "block", "source": "waf", "rule": "rule-1", "host": "good.example.com", "country": "US"}
				if got := testutil.ToFloat64(zoneFirewallEventsCount.With(firewallLabels)); got != 13 {
					t.Errorf("%s = %v, want 13", zoneFirewallEventsCountMetricName, got)
				}
				if got := testutil.ToFloat64(zoneEdgeErrorsByPath.With(prometheus.Labels{"zone": tt.zone, "account": "account", "status": "500", "host": "good.example.com", "path": "/users/:id"})); got != 17 {
					t.Errorf("%s = %v, want 17", zoneEdgeErrorsByPathMetricName, got)
				}
			}
		})
	}
}

func mustJSON(value any) []byte {
	b, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return b
}
