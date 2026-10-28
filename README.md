# Nodesk

A live, single-page map of your home network, a remote home (OpenWrt router), your cloud servers and your Tailscale tailnet. Runs on a Raspberry Pi. The interface is in English and Turkish (switch with the **EN / TR** button).

- **What is where:** which device is on which network and behind what (modem, router, extender); whether it is online and how much it was up in the last 7 days.
- **What is running:** services on the Pi and on your servers (Docker, CasaOS apps, system services) and their health.
- **How things connect:** who reaches whom over the tailnet directly or through a relay (DERP); who uses which exit node.
- **What changed:** optional notifications (ntfy or Telegram) for new devices, services going down, silent agents and exit node changes.

## Principles

- **No port scanning.** Devices are learned from what they say when joining (DHCP) and announcing themselves (mDNS, SSDP), and from the Pi's own ARP/neighbour table. Devices that do not announce a name get one name query per day (NetBIOS, mDNS): one packet per IP.
- **The Pi never connects to your devices.** Remote routers and servers push their own data to the Pi every 5 minutes (agents, with a key). Agents also fetch new versions from the Pi themselves.
- **No vendor-specific integrations.** Works regardless of modem, extender or router brand. There is an agent for OpenWrt routers and one for Linux servers.
- **No dependencies.** Python standard library and a single-file web UI; nginx in a container serves it.

## Requirements

- A Raspberry Pi (or any always-on Linux machine), Python 3.11+, Docker (with the compose plugin), Tailscale, `arp-scan`, `git`, `curl`
- Optional: an OpenWrt router (to add another home), Linux servers (to see their services)
- With CasaOS the web UI is installed as a CasaOS app, otherwise with `docker compose`.

```bash
sudo apt install -y git arp-scan curl
curl -fsSL https://get.docker.com | sh            # Docker + compose plugin
curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up
```

## Install

```bash
sudo git clone https://github.com/Contraill/Nodesk.git /DATA/AppData/nodesk/app
sudo /DATA/AppData/nodesk/app/bin/nodesk install
```

The data folder defaults to `/DATA/AppData/nodesk` (CasaOS layout). For another location pass `NODESK_HOME=/path` to both commands. The install can be re-run at any time; it repairs whatever is broken.

The map is at `http://<pi>:8088`. On first open a **setup wizard** appears:

1. The Pi's network (interface, subnet, gateway) is detected automatically; you give it a name.
2. You add other homes (router agent) and servers (server agent), if any.
3. You put Tailscale devices into groups (e.g. "Cloud", "Roaming devices").
4. You choose who can edit.

<details><summary>Using a private fork: read-only deploy key</summary>

```bash
sudo mkdir -p /DATA/AppData/nodesk/keys && sudo chmod 700 /DATA/AppData/nodesk/keys
sudo ssh-keygen -q -t ed25519 -N "" -C nodesk-deploy -f /DATA/AppData/nodesk/keys/deploy_ed25519
sudo cat /DATA/AppData/nodesk/keys/deploy_ed25519.pub   # GitHub > Settings > Deploy keys (no write access)
sudo git -c core.sshCommand="ssh -i /DATA/AppData/nodesk/keys/deploy_ed25519 -o IdentitiesOnly=yes" \
  clone git@github.com:<you>/Nodesk.git /DATA/AppData/nodesk/app
```
If the key exists, the installer uses it for updates as well.
</details>

## Other homes and servers: agents

**Settings > Agents > Add**. Each agent gets its own key; copy the install command and run it on that device. Running it again is safe.

| Agent | Where | What it sends |
|---|---|---|
| Router (OpenWrt) | `uclient-fetch -qO- '…' \| sh` (on the router) | DHCP leases, ARP table, the modem network on the WAN side (with `arp-scan`), listening services, exit node. With `ucode-mod-socket` installed: names devices announce over DHCP/mDNS and one name query per day |
| Server (Linux) | `curl -fsSL '…' \| sudo sh` | Docker containers, listening ports, exit node |

Each router agent becomes its own group (frame) on the map. The router's modem and Tailscale name are detected from its reports.

## Access

By default everyone on the network can see the map, but **only clients connecting over Tailscale can edit**, so a guest on your Wi-Fi cannot change settings. Under **Settings > Access** you can choose:

- only specific Tailscale accounts (identity checked with `tailscale whois`)
- password login (`sudo nodesk password` or from Settings)
- login required to see the map too

Agent endpoints are not affected by these settings; they are protected by their own keys.

## Device recognition

Names and types are looked up in this order:

1. the name you gave
2. the name the device sends over DHCP
3. its mDNS / NetBIOS / UPnP name
4. vendor (MAC) and operating system (DHCP fingerprint)

Phones use a different random MAC on every Wi-Fi network. MACs of the same phone are treated as one device when:
- they carry the same DHCP/mDNS name (factory default names do not count),
- they have the same name in `config.toml`,
- or you say "Same device".

If one disappears and another shows up right after, the map asks. The **N unnamed** link in the top bar lets you name all devices that do not announce a name on one screen.

Devices behind MAC-NAT extenders (repeaters) are shown separately. A device connected by both cable and Wi-Fi, and the two MACs of an extender, are not shown twice.

## Language

The UI defaults to English. The **EN / TR** button in the toolbar switches the language for your browser. When someone who can edit switches it, it also becomes the default for new visitors and the language of notifications. A link can force a language with `?lang=tr` or `?lang=en`.

## Updates

The map checks for a new version every 6 hours and shows it at the top. **Settings > Update**, or:

```bash
sudo nodesk update      # shows the changes, applies them, restarts the service and the web UI
sudo nodesk rollback    # goes back to the previous version
```

`config.toml`, edits made on the map, history and keys are kept. Agents fetch the new version on their next report.

## Commands

| Command | What it does |
|---|---|
| `sudo nodesk status` | Version, service, web UI, agents, last scan |
| `sudo nodesk run` | Scan now |
| `sudo nodesk logs 50` | Last log lines |
| `sudo nodesk password` | Edit password |
| `sudo nodesk agent add <name>` / `list` / `remove <name>` | Agents |
| `sudo nodesk install` | Repairs the installation |
| `sudo nodesk uninstall` | Removes everything (see below) |

## Uninstall

Two ways to remove Nodesk without leaving anything behind:
- `sudo nodesk uninstall` on the Pi
- delete the web UI (`nodesk-web`) in CasaOS (or Docker). If the container is gone for 10 minutes, removal starts by itself. Merely stopping it, or the short gap during an update, does not count.

The order is:
1. Each agent removes itself from its device on its next report: scheduler, listener service, files.
2. Then the service, the `nodesk` command, the web container and image, and the whole data folder are deleted from the Pi.

If the container comes back in the meantime, removal is cancelled. If an agent on a device that is off does not answer, its manual removal command is written to the log (`journalctl -u nodesk`).

To remove a single agent: **Settings > Agents > Delete**. The device removes itself, then the record is deleted.

## Data folder

```
app/              this repository (replaced by updates)
config.toml       advanced settings (most things are set on the map now)
data/
  settings.json   settings: groups, access, colors, notifications, language
  overrides.json  edits made on the map
  agents.json     agents and their keys; agents/ holds the latest reports
  passive*.json   what passive listening and the routers heard
  state.json      first/last seen; history.json covers the last 7 days
  auth.json       password hash and sessions (root only)
www/              public map data (empty when the map is private)
```

Every JSON file keeps its previous version as `.bak`. A corrupt file is moved aside (`.corrupt-<time>`) and the backup is used.

Running parts:
- `nodesk.service`: runs as root; collector, passive listener and API (127.0.0.1:8089 only).
- `nodesk-web`: nginx container serving the map on 8088 and proxying `/api/`.

## Troubleshooting

- **The map does not update:** `sudo nodesk status`, `sudo nodesk logs 100`.
- **A router group is grey:** the router agent is not reporting. On the router: `logread | grep nodesk-agent`, `/tmp/nodesk-install.log`.
- **No Edit button:** you are not connecting over Tailscale. Use the Tailscale address, or set a password with `sudo nodesk password` and log in.
- **Devices without names:** phones announce their name when they reconnect. Wait a day, or name them from the "N unnamed" screen.

## Development

```bash
tests/run.sh              # unit + API + script + UI tests (UI tests need Chromium)
tests/run.sh --preview    # + a preview with sample data at http://localhost:8099
```

The map has a self-test: add `#selftest` to the address. It checks for overlapping cards, lines crossing cards and JS errors. When releasing, bump `VERSION`; if the router side changed, bump `TOPO_VERSION` in `router/topo-collect`.

## License

[MIT](LICENSE)
