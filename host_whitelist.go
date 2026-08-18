package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"
)

const hostWhitelistPath = "/etc/cloudflare-exporter/hosts.yaml"

type hostWhitelist struct {
	enabled bool
	allowed map[string]struct{}
}

func emptyHostWhitelist() hostWhitelist {
	return hostWhitelist{allowed: map[string]struct{}{}}
}

func (w hostWhitelist) Allows(host string) bool {
	if !w.enabled || len(w.allowed) == 0 {
		return true
	}
	_, ok := w.allowed[host]
	return ok
}

func readHostWhitelist(path string) (hostWhitelist, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return emptyHostWhitelist(), "missing/unreadable", err
	}
	if len(b) == 0 {
		return emptyHostWhitelist(), "empty", errors.New("empty whitelist")
	}

	decoder := yaml.NewDecoder(bytes.NewReader(b))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return emptyHostWhitelist(), "malformed", errors.New("malformed whitelist")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return emptyHostWhitelist(), "malformed", errors.New("multiple whitelist documents")
	}

	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return emptyHostWhitelist(), "invalid schema", errors.New("whitelist must be one mapping")
	}
	root := document.Content[0]
	if len(root.Content) != 2 {
		return emptyHostWhitelist(), "invalid schema", errors.New("whitelist must contain only hosts")
	}
	var hosts *yaml.Node
	for i := 0; i < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		if key.Value == "<<" {
			return emptyHostWhitelist(), "invalid schema", errors.New("merge keys are not allowed")
		}
		if key.Value != "hosts" || hosts != nil {
			return emptyHostWhitelist(), "invalid schema", errors.New("invalid whitelist key")
		}
		hosts = value
	}
	if hosts == nil || hosts.Kind != yaml.SequenceNode {
		return emptyHostWhitelist(), "invalid schema", errors.New("hosts must be a list")
	}

	allowed := make(map[string]struct{}, len(hosts.Content))
	for _, host := range hosts.Content {
		if host.Kind != yaml.ScalarNode || host.Tag != "!!str" {
			return emptyHostWhitelist(), "invalid schema", errors.New("hosts must contain strings")
		}
		allowed[host.Value] = struct{}{}
	}
	return hostWhitelist{enabled: true, allowed: allowed}, "", nil
}

func loadHostWhitelist(path string, previous hostWhitelist) hostWhitelist {
	if path == "" {
		return emptyHostWhitelist()
	}
	next, category, err := readHostWhitelist(path)
	if err != nil {
		log.WithField("path", path).WithField("category", category).Warn("host whitelist reload failed")
		if previous.enabled {
			return previous
		}
		return emptyHostWhitelist()
	}
	if !sameHostWhitelist(previous, next) {
		log.WithField("path", path).WithField("hosts", len(next.allowed)).Info("host whitelist replaced")
	}
	return next
}

func sameHostWhitelist(a, b hostWhitelist) bool {
	if a.enabled != b.enabled || len(a.allowed) != len(b.allowed) {
		return false
	}
	for host := range a.allowed {
		if _, ok := b.allowed[host]; !ok {
			return false
		}
	}
	return true
}

type hostSeriesVector interface {
	DeleteLabelValues(labelValues ...string) bool
}

type hostSeriesFamily struct {
	vector   hostSeriesVector
	labels   []string
	emitted  map[string]map[string]struct{}
	observed map[string]map[string]struct{}
}

type hostSeriesRegistry struct {
	mu       sync.Mutex
	families []hostSeriesFamily
}

func newHostSeriesRegistry() *hostSeriesRegistry { return &hostSeriesRegistry{} }

var hostSeriesRegistryState = newHostSeriesRegistry()

func (r *hostSeriesRegistry) Register(vector hostSeriesVector, labels ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.families = append(r.families, hostSeriesFamily{
		vector:   vector,
		labels:   labels,
		emitted:  map[string]map[string]struct{}{},
		observed: map[string]map[string]struct{}{},
	})
}

func (r *hostSeriesRegistry) Observe(vector hostSeriesVector, labels prometheus.Labels) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.families {
		if r.families[i].vector != vector {
			continue
		}
		values := make([]string, len(r.families[i].labels))
		for j, label := range r.families[i].labels {
			values[j] = labels[label]
		}
		host := labels["host"]
		key, _ := json.Marshal(values)
		if r.families[i].observed[host] == nil {
			r.families[i].observed[host] = map[string]struct{}{}
		}
		r.families[i].observed[host][string(key)] = struct{}{}
		return
	}
}

func deleteHostSeriesTuples(family *hostSeriesFamily, tuples map[string]struct{}) {
	for key := range tuples {
		var values []string
		if err := json.Unmarshal([]byte(key), &values); err == nil {
			family.vector.DeleteLabelValues(values...)
		}
	}
}

func (r *hostSeriesRegistry) ResetScrape() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.families {
		r.families[i].observed = map[string]map[string]struct{}{}
	}
}

func (r *hostSeriesRegistry) Reconcile() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.families {
		family := &r.families[i]
		for host, emitted := range family.emitted {
			observed := family.observed[host]
			stale := make(map[string]struct{})
			for key := range emitted {
				if _, ok := observed[key]; !ok {
					stale[key] = struct{}{}
				}
			}
			deleteHostSeriesTuples(family, stale)
		}
		family.emitted = family.observed
		family.observed = map[string]map[string]struct{}{}
	}
}
