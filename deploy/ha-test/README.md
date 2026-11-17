# Home Assistant source test (T24.21)

`e2e.sh` checks TelltaleDNS's Home Assistant source and the TelltaleDNS integration against a real
Home Assistant. It never touches your Home Assistant: it starts a throwaway one in Docker
(`compose.yaml`, its own Compose project, port 18124 on 127.0.0.1), and removes it at the end.

```sh
deploy/ha-test/e2e.sh target/debug/telltale
```

On Windows, with the dev container (`wrendns-dev`) holding the build, run the binary from its volumes:

```sh
TELLTALE_VOLUMES_FROM=wrendns-dev deploy/ha-test/e2e.sh /target/hatest/debug/telltale
```

What it does, in order:

1. Starts Home Assistant and onboards a generated owner through the onboarding API.
2. Makes a long-lived token through the websocket API, inside the Home Assistant container. The
   token and the generated password are kept in a temporary file and are never printed.
3. Seeds four fake devices through `fixtures/telltale_seed` (a test-only integration): a device
   with a name a person gave it, two with the integration's name, and one with no address.
   Addresses come from `device_tracker` states.
4. Runs a TelltaleDNS node in a throwaway container on the same network, with
   `[[router]] type = "home_assistant"` reading that Home Assistant. It checks the names, MACs and
   addresses the node reports: the three devices with addresses are named, the one with no
   address is absent.
5. Asks the node's DNS for each name (`kitchen-tablet.home.arpa` and the rest) and checks the
   address.
6. Sets up the TelltaleDNS integration in Home Assistant with an agent token (`analytics:read`,
   `config:read`), then checks its sensors: known devices (3, all with DNS names, from
   `home-assistant`), health, the problem sensor (on only when health isn't healthy), queries and
   version.

A trap always removes the node container, the Home Assistant containers and volumes, and the
temporary directory, also when a step fails. The failure output shows the last lines of the node's
and Home Assistant's logs.

Environment: `HA_TEST_PORT` (18124), `NODE_API_PORT` (18053), `NODE_DNS_PORT` (18153) choose the
host ports. Needs Docker, curl and Python 3 (or `python` on Windows), and the `ubuntu:24.04` image.

CI runs it as the `ha-test` job in `.github/workflows/home-assistant.yml` (20 minutes), with a
debug build of the binary.

The Docker Desktop bundle's `test-ha` profile (`deploy/docker-desktop/compose.yaml`) is the same
Home Assistant for trying things by hand. This script uses its own Compose project so that it
never starts the bundle's `telltale` service.

Decision record: ADR-955 in `spec/11-decisions.md`.
