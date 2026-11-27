# WrenDNS with the Home Assistant OpenTelemetry Collector add-on

This page is for a house where Home Assistant already sends its logs, traces and metrics to an OpenTelemetry backend through the community add-on [ha-addon-otelcol](https://github.com/nicolastakashi/ha-addon-otelcol) (a separate Apache-2.0 project; nothing of it is bundled with WrenDNS), and you want the DNS data in the same place.

## What the add-on does and does not do

The add-on runs an OpenTelemetry Collector on Home Assistant OS. It reads Home Assistant's journal, events, entity states and host metrics, and **exports** them to the backend named in its `otlp_endpoint` option (`otlp_protocol` `http` or `grpc`, `otlp_headers`, `otlp_ca_file`).

It does **not** expose an OTLP receiver to the network. The only listeners its documentation describes bind to the loopback address of the Home Assistant host (`127.0.0.1:4040` for profiles, and `127.0.0.1:4318`, which takes profiles only), and it has no option for extra receivers or a custom collector configuration. So WrenDNS cannot send to the add-on, and the add-on cannot forward WrenDNS's data. Point WrenDNS at the same backend the add-on uses, or at a collector of your own that forwards to it. Check the add-on's current documentation if this changes.

## Setup 1: WrenDNS sends straight to the same backend

Use this when the backend takes OTLP/HTTP with JSON (the OpenTelemetry Collector and Grafana Alloy do, and so do most hosted backends; ask yours before relying on it, since some take protobuf only).

1. In Settings -> Telemetry, **OpenTelemetry metrics export**, choose **Set up the export** and enter the backend's base address, for example `https://otlp.example.net` (no `/v1/metrics`: WrenDNS adds the path for each signal). Or in the configuration file:
   ```toml
   [telemetry.otlp]
   endpoint = "https://otlp.example.net"
   interval_secs = 60
   compression = "gzip"                    # optional; the same JSON, gzip-compressed
   header_refs = { "authorization" = "otlp-backend" }   # a stored secret, see "Headers" below
   ```
2. Use the same credentials the add-on uses (`otlp_headers` there). Enter each header's value in the UI as a stored secret; it is encrypted, replicated and never shown again.
3. For logs and traces, see "What arrives" below.

## Setup 2: a collector of your own in between

Use this when the backend wants protobuf or gRPC, or when you want one place to add attributes. Run any OpenTelemetry Collector on a machine on your network, for example at `192.168.1.40`, with an OTLP/HTTP receiver and an exporter to your backend:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318     # accepts JSON and gzip-compressed requests

processors:
  resource:
    attributes:
      # Match the add-on's deployment_environment so a dashboard can filter on both.
      - key: deployment.environment
        value: home
        action: upsert

exporters:
  otlphttp:
    endpoint: https://otlp.example.net
    headers:
      authorization: "Bearer ${env:OTLP_TOKEN}"

service:
  pipelines:
    metrics: { receivers: [otlp], processors: [resource], exporters: [otlphttp] }
    logs:    { receivers: [otlp], processors: [resource], exporters: [otlphttp] }
    traces:  { receivers: [otlp], processors: [resource], exporters: [otlphttp] }
```

Then set WrenDNS's `endpoint` to `http://192.168.1.40:4318`. Port 4318 is the OTLP/HTTP default (4317 is gRPC, which WrenDNS does not speak). Keep that port on your LAN: a collector's receiver has no authentication unless you add it, and what arrives is your query data.

## What arrives

| Signal | Set up in | Path | Notes |
|---|---|---|---|
| Metrics | the export card, or `[telemetry.otlp]` | `<endpoint>/v1/metrics` | Everything `/metrics` serves, every `interval_secs`. |
| Traces | `traces_sample_every`, `traces_slow_ms` in `[telemetry.otlp]` (file, read at start) | `<endpoint>/v1/traces` | A server span for the query, a client span for the upstream wait. |
| Logs | an event sink with `format = "otlp_logs"` (Settings -> Telemetry, **Event sinks**) | the sink's own URL, `<endpoint>/v1/logs` | One record per query event. The sink has its own request path: the export's `compression` does not apply to it, and its token is the sink's. |

Every signal carries the resource attributes `service.name = wrendns`, `service.version`, `host.name` and `service.instance.id`, both set to the node's name, so the nodes of a cluster are told apart. Home Assistant's signals carry `service.name = homeassistant` (the add-on's `service_name`) and its own `service.instance.id` if set; give the add-on's `service_instance_id` a value that is not one of your node names. Join a DNS dashboard with Home Assistant's on `deployment.environment` (add it in your collector as above) and on the device name where a log record carries `client.name`.

Query data leaves the node when you do this. The privacy rules are unchanged: the query log's privacy level decides whether names are hashed and whether client addresses are sent, sampling decides how many traces go, and a device's name is in log records unless the level removes the client.

## Headers, TLS and compression

- **Headers.** Each header's value is a stored secret named in `header_refs` (the card handles this). An inline `headers` entry is possible in the file only and is shown as `<redacted>`.
- **Compression.** `compression = "gzip"` sends the metrics and trace requests gzip-compressed with `Content-Encoding: gzip`. The body is still JSON. A collector's OTLP/HTTP receiver accepts it; a backend that does not answers with an error status, which shows in the log as "OTLP metrics not delivered". Turn it off for such a backend. In a cluster, the first save with gzip waits until every member's build knows the option (409 `upgrade_required` names the member).
- **TLS.** An `https://` endpoint is checked against the system's trusted roots. A private CA file for the collector is not available yet: use a public certificate, or a plain `http://` address on a trusted LAN.
- **Not available.** OTLP over protobuf or gRPC.

## Checking that it works

- On the card: **Exporting from this node**. `wrendns_traces_total{result="failed"}` counts trace requests the collector did not take.
- In the collector, add a `debug` exporter with `verbosity: detailed` to a pipeline and watch the records arrive.
- The repository's tests run the exporter against a local fake OTLP/HTTP receiver and check that metrics and traces arrive plain and gzip, and logs plain only (gzip for an event sink is an open item), with the headers and attributes above (`cargo test -p wrendns receiver_` runs all four).
