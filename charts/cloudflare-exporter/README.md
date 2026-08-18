# CloudFlare Prometheus exporter Helm Chart

[<img src="ll-logo.png">](https://lablabs.io/)

We help companies build, run, deploy and scale software and infrastructure by embracing the right technologies and principles. Check out our website at https://lablabs.io/

---

## Description

A helm chart for [cloudflare-exporter](https://github.com/lablabs/cloudflare-exporter)

## Configuration


The following table lists the configurable parameters of the Cloudflare-exporter chart and their default values.

| Parameter                | Description             | Default        |
| ------------------------ | ----------------------- | -------------- |
| `replicaCount` |  | `1` |
| `image.repository` |  | `"ghcr.io/lablabs/cloudflare_exporter"` |
| `image.pullPolicy` |  | `"Always"` |
| `image.tag` |  | `"0.0.2"` |
| `env` |  | `[]` |
| `secretRef` | The name of a secret with environment variables | `""` |
| `hostWhitelist.configMapName` | External ConfigMap containing the `hosts.yaml` whitelist key | `""` |
| `imagePullSecrets` |  | `[]` |
| `nameOverride` |  | `""` |
| `fullnameOverride` |  | `""` |
| `podAnnotations` |  | `{}` |
| `podSecurityContext` |  | `{}` |
| `priorityClassName` |  | `""` |
| `securityContext` |  | `{}` |
| `service.type` |  | `"ClusterIP"` |
| `service.port` |  | `8080` |
| `service.annotations.prometheus.io/probe` |  | `"true"` |
| `serviceAccount.enabled` |  | `false` |
| `serviceAccount.annotations` |  | `{}` |
| `serviceAccount.name` |  | `""` |
| `serviceMonitor.enabled` |  | `false` |
| `serviceMonitor.namespace` |  | `""` |
| `serviceMonitor.labels` |  | `{}` |
| `serviceMonitor.interval` |  | `"30s"` |
| `serviceMonitor.telemetryPath` |  | `"/metrics"` |
| `serviceMonitor.timeout` |  | `"10s"` |
| `serviceMonitor.relabelings` |  | `[]` |
| `serviceMonitor.targetLabels` |  | `[]` |
| `serviceMonitor.metricRelabelings` |  | `[]` |
| `resources` |  | `{}` |
| `nodeSelector` |  | `{}` |
| `tolerations` |  | `[]` |
| `affinity` |  | `{}` |

When configured, the operator must create `hostWhitelist.configMapName` in the release namespace. The chart projects only `hosts.yaml` read-only into `/etc/cloudflare-exporter`; it does not create or own a ConfigMap. The runtime default path is `/etc/cloudflare-exporter/hosts.yaml`. Before any valid whitelist is loaded, a missing or unmounted ConfigMap means scrape all hosts. A valid `hosts: []` also means scrape all hosts. After a valid non-empty whitelist is loaded, an unreadable or missing file retains the last valid whitelist. See `examples/host-whitelist-configmap.yaml`, `ci/host-whitelist-values.yaml`, and `ci/assert-host-whitelist-render.sh`.



## Contributing and reporting issues

Feel free to create an issue in this repository if you have questions, suggestions or feature requests.
