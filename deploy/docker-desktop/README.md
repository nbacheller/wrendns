# Trying the fork on Docker Desktop

This bundle runs this fork's WrenDNS in Docker Desktop on Windows or macOS, so you can try the network-inventory features (milestone M22 in `spec/10`) against your own UniFi gateway and Home Assistant:

- **Router names:** device names from your UniFi console. That covers connected clients, plus reserved devices while they're offline.
- **Home Assistant names:** the names you gave devices in Home Assistant.
- **Names in DNS:** those names answered as `kitchen-tablet.home.arpa`, with reverse lookups.
- **Network inventory:** your LANs and VLANs, with how full each one is.
- **Optional test HA:** a throwaway Home Assistant with the WrenDNS integration (`integrations/home-assistant`), so your real one stays untouched.

WrenDNS only **reads** from the gateway and from Home Assistant. It changes nothing on either.

## What Docker Desktop can and can't show

Docker Desktop runs containers inside a small VM:

- **What doesn't work:** every DNS query reaches WrenDNS from the VM's address, and the container can't see your LAN's ARP table or mDNS. Per-device statistics and rules won't line up with your real devices here.
- **What works:** the gateway and Home Assistant reads are ordinary outgoing HTTPS, so they behave here exactly as they will on a Pi. So do the device names, the DNS answers, and the networks.

For real per-device use, run WrenDNS with host networking on a Pi or a Linux host (`deploy/compose`).

## 1. Credentials

Put two files in `secrets/`. That folder is git-ignored, and both files are mounted read-only.

| File | What | Where to get it |
|---|---|---|
| `secrets/unifi-key` | A UniFi Network API key | UniFi Network → **Settings → Control Plane → Integrations → Create API Key**. |
| `secrets/ha-token` | A Home Assistant long-lived access token | In Home Assistant, create a dedicated user (for example `wrendns`) and make it an **administrator**: the registry is read through `/api/template`, which only administrators may use. Log in as that user, open its profile → **Security** → **Long-lived access tokens** → **Create token**. |

Each file holds just the key or token on one line. On macOS, keep the files readable by others (`chmod 644 secrets/*`), because the container's user isn't you.

> **Why an administrator token?** WrenDNS only sends one read-only template that lists device names and MAC addresses. Any administrator token can do much more than that, though, so keep it in this folder and revoke it in Home Assistant when you're done testing.

## 2. Addresses

Edit `wrendns.toml`:

- `[[router]] gateway` → `url`: your UniFi console's address (for example `https://192.0.2.1`).
- `[[router]] home-assistant` → `url`: your Home Assistant (`http://homeassistant.local:8123`).

The gateway's certificate is self-signed, so the file starts with `tls_insecure_skip_verify = true`. To verify the gateway properly instead, save its certificate:

```sh
openssl s_client -connect 192.0.2.1:443 </dev/null | openssl x509 > secrets/ucg.pem
openssl x509 -in secrets/ucg.pem -noout -ext subjectAltName     # usually unifi.local
```

Then replace `tls_insecure_skip_verify` with `tls_ca = "/run/secrets/ucg.pem"` and `tls_server_name = "unifi.local"`.

## 3. Build and start

```sh
cd deploy/docker-desktop
docker compose up -d --build
docker compose logs -f wrendns          # Ctrl-C to stop following
```

The first build compiles the UI and the Rust binary (expect 10–20 minutes; later builds reuse the cache).

Within a few seconds of starting, the log should show:

```text
router integration: devices read router=gateway devices=… networks=…
Home Assistant: devices read router=home-assistant devices=… matched=…
device names in DNS: updated domain=home.arpa names=…
```

- `matched` is how many of Home Assistant's devices got an address from the gateway. Home Assistant knows MAC addresses, and the gateway knows which address each MAC has now.
- If the log says some optional reads didn't work, the key can read connected clients but not reservations or networks. Names of connected devices still come through.

Create the admin:

```sh
docker compose exec wrendns wrendns auth setup-token
```

Then open <http://localhost:8053/> and sign in with that token.

## 4. What to look at

- **Clients → Discovered:** every device from the gateway and Home Assistant, with the name each one gave.
- **Names in DNS.** Ask from a container, through the published port (`-port=1053` works there):

  ```sh
  docker run --rm alpine nslookup -port=1053 kitchen-tablet.home.arpa host.docker.internal   # use a name from the list
  docker run --rm alpine nslookup -port=1053 192.0.2.21 host.docker.internal               # reverse lookup
  ```

  A reverse lookup for an address that no known device has answers `NXDOMAIN`, which is a correct answer.

  `host.docker.internal` is a name that Docker Desktop (Windows and macOS) sets up for the host. The container commands above need Docker Desktop; on a Linux Docker Engine, use the host's LAN address instead.

  **Why not `nslookup -port=1053 ... 127.0.0.1` on Windows?** On Windows 11 (build 10.0.26200), `nslookup -port=1053`, the interactive `set port=1053`, and `-vc` all fail against this bundle: UDP prints `No response from server` and `-vc` prints `Unspecified error`. These results were re-checked on 2026-11-17 on one Windows 11 build. An earlier capture, not repeated, used a relay on port 53 in front of the bundle: nslookup sent nothing to the chosen port and six packets to port 53, and the bundle's answers were well formed and printed. So the fault is in the client, not in WrenDNS, but the cause of nslookup's port handling is not documented by Microsoft. Use a tool that honours a port from Windows instead, such as Python (which needs no extra install):

  ```powershell
  python -c "import socket,struct;q=struct.pack('>HHHHHH',0x1234,0x100,1,0,0,0)+b'\x07example\x03com\x00'+struct.pack('>HH',1,1);s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.sendto(q,('127.0.0.1',1053));r=s.recv(512);print('flags',r[2:4].hex(),'answers',struct.unpack('>H',r[6:8])[0])"
  ```

  It prints `flags 8180 answers 2` when the bundle answers `example.com` (a public name, so the answers depend on upstream DNS).

  A made-up name such as `definitely-not-here-xyz.example` gets `NXDOMAIN`, so the bundle has no wildcard record. A public name such as `example.com` is answered from upstream DNS, not from a home-network record.

- **The inventory, through the API.** Create a token under **Settings → Users → API tokens**, then:

  ```sh
  curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8053/api/v1/networks
  curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8053/api/v1/dhcp/leases
  ```

  Each network shows its subnet, VLAN, DHCP pool, group, device count, and how full it is. Each device shows its `router` (which source named it) and its `dnsName`.
- **Explain** a device name (`kitchen-tablet.home.arpa`). It says the name was answered from the devices WrenDNS knows by name.

## 5. Optional: the Home Assistant integration in a test Home Assistant

```sh
docker compose --profile test-ha up -d
```

1. Open <http://localhost:8124/> and create a user. This is a fresh Home Assistant, separate from yours.
2. In WrenDNS, open **Settings → Users → API tokens** and create an **agent** token named `home-assistant` with these scopes:
   - `analytics:read` and `config:read`, to watch;
   - `ops:pause`, for the blocking switches;
   - `ops:anomalies`, to acknowledge findings;
   - `config:write:clients`, for quarantine.
3. In the test Home Assistant, go to **Settings → Devices & services → Add integration → WrenDNS**:
   - **Address:** `http://wrendns:8053`;
   - **Token:** the agent token.

You get:

- sensors: queries, blocked, cache hits, upstream latency, health, open anomalies, known devices, and networks;
- a **Blocking** switch for everyone, plus one per group;
- actions: pause, resume, quarantine a device, release it, and acknowledge anomalies;
- a `wrendns_anomaly` event for each new device anomaly.

To check the source and the integration against a throwaway Home Assistant without starting this bundle's services, run `deploy/ha-test/e2e.sh` (its own Compose project; see `deploy/ha-test/README.md`).

`integrations/home-assistant/README.md` has example automations. When you're happy with it, copy `integrations/home-assistant/custom_components/wrendns` into your real Home Assistant's `config/custom_components/` and restart. Then use `http://<this computer's LAN address>:8053` as the address; you may need to allow port 8053 through your computer's firewall.

## Stopping and cleaning up

```sh
docker compose --profile test-ha down          # keeps the data volumes
docker compose --profile test-ha down -v       # also deletes them
```

Then revoke the Home Assistant token and the UniFi API key you made for this.
