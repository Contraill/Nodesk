"""Nodesk testleri: gerçek çıktılardan alınmış örneklerle (tests/fixtures).

    python3 -m unittest discover -s tests -v
"""

import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures")
sys.path.insert(0, ROOT)
NOW = "2026-10-27T14:00:00+00:00"
os.environ["NODESK_NOW"] = NOW
os.environ["NODESK_OUI"] = os.path.join(FIX, "ieee-oui.txt")
os.environ["NODESK_CONFIG"] = os.path.join(ROOT, "config.example.toml")

from nodesk import agents, passive, server, sources, store, util  # noqa: E402


def make_home():
    home = tempfile.mkdtemp(prefix="nodesk-test-")
    st = store.Store(store.Paths(home))
    for name, kind, fixture in (("router", "router", "router.txt"),
                                ("cloud-arm", "linux", "agent_cloud-arm.txt")):
        st.add_agent(name, kind)
        with open(os.path.join(FIX, fixture), encoding="utf-8") as f:
            st.save_report(name, f.read(), "100.64.0.2")
    return home


class CollectTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = make_home()
        app = server.App(cls.home, FIX)
        assert app.collect()
        with open(os.path.join(cls.home, "www", "data.json"), encoding="utf-8") as f:
            cls.data = json.load(f)
        cls.ids = {n["id"]: n for n in cls.data["nodes"]}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.home, ignore_errors=True)

    def test_no_errors(self):
        self.assertEqual(self.data["errors"], [])

    def test_pi_services_grouped(self):
        svcs = self.ids["self"]["services"]
        orbis = [s for s in svcs if s.get("app") == "media-app"]
        self.assertEqual(sorted(s["name"] for s in orbis), ["media-app-backend", "media-app-frontend"])
        self.assertTrue(all(s["app_name"] == "Orbis" for s in orbis), "config [apps] adı")
        gitea = next(s for s in svcs if s["name"] == "gitea")
        self.assertEqual(gitea["app_name"], "Gitea", "CasaOS başlığı okunuyor")
        self.assertEqual(gitea["ports"], [2222, 3002])
        system = {s["name"]: s["ports"] for s in svcs if s["source"] == "system"}
        self.assertEqual(system.get("CasaOS"), [80])
        self.assertEqual(system.get("Samba"), [139, 445])
        self.assertIn("SSH", system)
        self.assertNotIn("nginx", system, "host ağındaki nodesk-web iki kez sayılmıyor")
        web = next(s for s in svcs if s["name"] == "nodesk-web")
        self.assertEqual(web["ports"], [8088])

    def test_self_not_duplicated(self):
        self.assertNotIn("mac:88:a2:9e:35:f8:bc", self.ids)
        self.assertNotIn("mac:88:a2:9e:35:f8:b1", self.ids)

    def test_passive_names_and_types(self):
        s24 = self.ids["mac:a6:8e:da:14:ea:d0"]
        self.assertEqual(s24["label"], "S24", "config adı DHCP adından önce gelir")
        self.assertTrue(s24["online"])
        tv = self.ids["mac:b4:e6:2a:c2:32:4a"]
        self.assertTrue(tv["online"])
        pc = self.ids["mac:f0:2f:74:aa:bb:cc"]
        self.assertEqual(pc["label"], "DESKTOP-K7Q2", "DHCP adı kullanılıyor")
        self.assertEqual(pc["kind"], "pc")
        self.assertIn("passive", pc["via"])
        toshiba = self.ids["mac:70:54:b4:5a:b6:4e"]
        self.assertTrue(toshiba["online"], "arp taramasında yanıt verdi")

    def test_neigh_adds_device(self):
        n = self.ids["mac:9c:8e:cd:01:02:03"]
        self.assertFalse(n["online"], "STALE komşu çevrimiçi sayılmaz")
        self.assertNotIn("mac:02:42:ac:11:00:02", self.ids, "docker ağı dahil değil")

    def test_router_via_agent(self):
        self.assertEqual(self.ids["router"]["parent"], "mac:c0:49:43:1c:cc:12")
        self.assertEqual(self.ids["mac:1c:af:4a:55:4b:2c"]["parent"], "router")
        self.assertFalse(self.ids["mac:aa:bb:cc:00:11:22"]["online"])
        self.assertTrue(any(o["from"] == "router" and o["to"] == "self" for o in self.data["overlay"]))
        self.assertTrue(self.data["router_script"]["ok"])

    def test_linux_agent_services(self):
        arm = self.ids["ts:cloud-arm"]
        names = {s["name"]: s for s in arm["services"]}
        self.assertEqual(names["edge-caddy"]["ports"], [80, 443])
        self.assertEqual(names["edge-api"]["ports"], [], "127.0.0.1 portu dışarı açık sayılmaz")
        self.assertEqual(names["edge-caddy"]["app"], "edge")
        self.assertIn("SSH", names)
        self.assertTrue(arm["agent"]["fresh"])

    def test_sources_status(self):
        for k in ("tailscale", "arp", "neigh", "docker", "host_ports"):
            self.assertTrue(self.data["sources"][k]["ok"], k)


class PassiveTest(unittest.TestCase):
    def eth(self, src, dst, etype, payload):
        mac = lambda s: bytes(int(x, 16) for x in s.split(":"))
        return mac(dst) + mac(src) + struct.pack("!H", etype) + payload

    def udp(self, src_ip, dst_ip, sport, dport, payload):
        udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
        return ip + udp

    def test_arp(self):
        arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, bytes.fromhex("aabbccddeeff"),
                          socket.inet_aton("192.168.44.50"), b"\0" * 6, socket.inet_aton("192.168.44.1"))
        obs = passive.parse_frame(self.eth("aa:bb:cc:dd:ee:ff", "ff:ff:ff:ff:ff:ff", 0x0806, arp))
        self.assertEqual(obs, [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.44.50", "via": "arp"}])

    def test_dhcp_request_hostname(self):
        b = bytearray(240)
        b[0] = 1
        b[28:34] = bytes.fromhex("d261e56d9ac3")
        b[236:240] = b"\x63\x82\x53\x63"
        opts = bytes([53, 1, 3, 50, 4]) + socket.inet_aton("192.168.44.8") + \
            bytes([12, 10]) + b"Galaxy-S24" + bytes([60, 15]) + b"android-dhcp-14" + b"\xff"
        frame = self.eth("d2:61:e5:6d:9a:c3", "ff:ff:ff:ff:ff:ff", 0x0800,
                         self.udp("0.0.0.0", "255.255.255.255", 68, 67, bytes(b) + opts))
        (o,) = passive.parse_frame(frame)
        self.assertEqual(o["mac"], "d2:61:e5:6d:9a:c3")
        self.assertEqual(o["ip"], "192.168.44.8")
        self.assertEqual(o["dhcp_name"], "Galaxy-S24")
        self.assertEqual(o["dhcp_vendor"], "android-dhcp-14")

    def test_mdns_response(self):
        def name(*labels):
            return b"".join(bytes([len(x)]) + x.encode() for x in labels) + b"\0"
        hdr = struct.pack("!HHHHHH", 0, 0x8400, 0, 3, 0, 0)
        ptr_rdata = name("Salon TV", "_googlecast", "_tcp", "local")
        rr1 = name("_googlecast", "_tcp", "local") + struct.pack("!HHIH", 12, 1, 120, len(ptr_rdata)) + ptr_rdata
        txt = bytes([7]) + b"fn=Salon" + b""
        txt = bytes([11]) + b"fn=Salon TV" + bytes([10]) + b"md=webOSTV"
        rr2 = name("Salon TV", "_googlecast", "_tcp", "local") + struct.pack("!HHIH", 16, 1, 120, len(txt)) + txt
        rr3 = name("LGwebOSTV", "local") + struct.pack("!HHIH", 1, 0x8001, 120, 4) + socket.inet_aton("192.168.44.101")
        frame = self.eth("b4:e6:2a:c2:32:4a", "01:00:5e:00:00:fb", 0x0800,
                         self.udp("192.168.44.101", "224.0.0.251", 5353, 5353, hdr + rr1 + rr2 + rr3))
        (o,) = passive.parse_frame(frame)
        self.assertEqual(o["mdns_name"], "LGwebOSTV")
        self.assertEqual(o["mdns_services"], ["_googlecast._tcp"])
        self.assertEqual(o["mdns_instances"], ["Salon TV"])
        self.assertEqual(o["friendly"], "Salon TV")
        self.assertEqual(o["model"], "webOSTV")

    def test_ssdp(self):
        msg = (b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nSERVER: Linux/4.4 UPnP/1.0 "
               b"WebOS/1.5\r\nNT: upnp:rootdevice\r\n\r\n")
        frame = self.eth("38:8c:50:9f:be:1c", "01:00:5e:7f:ff:fa", 0x0800,
                         self.udp("192.168.44.105", "239.255.255.250", 1900, 1900, msg))
        (o,) = passive.parse_frame(frame)
        self.assertIn("WebOS", o["ssdp_server"])

    def test_garbage_safe(self):
        for pkt in (b"", b"\0" * 13, os.urandom(60), self.eth("aa:bb:cc:dd:ee:ff", "ff:ff:ff:ff:ff:ff",
                                                              0x0800, self.udp("1.1.1.1", "2.2.2.2", 5353, 5353, os.urandom(40)))):
            try:
                passive.parse_frame(pkt)
            except (ValueError, struct.error, IndexError):
                pass

    def test_observe_filters_routed(self):
        p = passive.Passive(os.path.join(tempfile.mkdtemp(), "p.json"), subnet="192.168.44.0/24")
        p.observe({"mac": "6c:11:ba:f9:55:ab", "ip": "8.8.8.8", "via": "mdns"})
        p.observe({"mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.44.70", "via": "arp"})
        p.observe({"mac": "01:00:5e:00:00:fb", "ip": "192.168.44.71", "via": "arp"})
        self.assertEqual(list(p.snapshot()), ["aa:bb:cc:dd:ee:01"])


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = make_home()
        cls.port = _free_port()
        os.environ["NODESK_API_PORT"] = str(cls.port)
        server.API_PORT = cls.port
        cls.thread = threading.Thread(target=server.serve, args=(cls.home, FIX), daemon=True)
        cls.thread.start()
        for _ in range(100):
            try:
                if cls.get("/api/state")["scan"]["last_end"]:
                    break
            except OSError:
                pass
            time.sleep(0.1)

    @classmethod
    def get(cls, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{cls.port}{path}", timeout=5) as r:
            return json.loads(r.read())

    @classmethod
    def call(cls, method, path, body=None, ctype="application/json", raw=None):
        data = raw if raw is not None else json.dumps(body or {}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{cls.port}{path}", data=data, method=method,
                                     headers={"Content-Type": ctype})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def data(self):
        with open(os.path.join(self.home, "www", "data.json"), encoding="utf-8") as f:
            return {n["id"]: n for n in json.load(f)["nodes"]}

    def test_state(self):
        s = self.get("/api/state")
        self.assertIn("phone", s["types"])
        self.assertTrue(s["settings"]["auto"])

    def test_rename_device(self):
        st, _ = self.call("PUT", "/api/device?id=mac:9c:8e:cd:01:02:03",
                          {"name": "Mutfak tableti", "type": "tablet", "tags": "mutfak, IoT",
                           "services": [{"name": "Panel", "port": "8123"}]})
        self.assertEqual(st, 200)
        n = self.data()["mac:9c:8e:cd:01:02:03"]
        self.assertEqual(n["label"], "Mutfak tableti")
        self.assertEqual(n["kind"], "tablet")
        self.assertEqual(n["tags"], ["IoT", "mutfak"])
        self.assertEqual(n["services"][0]["ports"], [8123])
        self.call("PUT", "/api/device?id=mac:9c:8e:cd:01:02:03", {})
        self.assertFalse(self.data()["mac:9c:8e:cd:01:02:03"]["edited"])

    def test_parent_cycle_is_fixed(self):
        self.call("PUT", "/api/device?id=router", {"parent": "mac:1c:af:4a:55:4b:2c"})
        n = self.data()
        self.assertNotEqual(n["router"]["parent"], "mac:1c:af:4a:55:4b:2c")
        self.call("PUT", "/api/device?id=router", {})

    def test_rename_app(self):
        self.call("PUT", "/api/app?id=gitea", {"name": "Git sunucusu"})
        svc = next(s for s in self.data()["self"]["services"] if s["name"] == "gitea")
        self.assertEqual(svc["app_name"], "Git sunucusu")
        self.call("PUT", "/api/app?id=gitea", {})

    def test_csrf_and_validation(self):
        st, _ = self.call("PUT", "/api/device?id=x", raw=b"name=a", ctype="application/x-www-form-urlencoded")
        self.assertEqual(st, 415)
        st, _ = self.call("PUT", "/api/device?id=x", {"type": "uzay gemisi"})
        self.assertEqual(st, 400)
        st, _ = self.call("PUT", "/api/settings", {"interval_min": 7})
        self.assertEqual(st, 400)

    def test_settings(self):
        st, body = self.call("PUT", "/api/settings", {"interval_min": 15, "sources": {"arp": False}})
        self.assertEqual(st, 200)
        self.assertEqual(json.loads(body)["interval_min"], 15)
        self.assertFalse(self.get("/api/state")["settings"]["sources"]["arp"])
        self.call("PUT", "/api/settings", {"interval_min": 5, "sources": {"arp": True}})

    def test_agents_and_ingest(self):
        st, body = self.call("POST", "/api/agents", {"name": "cloud-amd-1", "kind": "linux"})
        self.assertEqual(st, 200)
        ag = next(a for a in json.loads(body) if a["name"] == "cloud-amd-1")
        cmd = ag["commands"]["direct"]
        self.assertIn("curl -fsSL", cmd)
        token = cmd.split("token=")[1].split("'")[0]
        st, script = self.call("GET", f"/api/agent/install?name=cloud-amd-1&token={token}", raw=None) \
            if False else (200, urllib.request.urlopen(
                f"http://127.0.0.1:{self.port}/api/agent/install?name=cloud-amd-1&token={token}").read().decode())
        self.assertIn("nodesk-agent", script)
        self.assertEqual(subprocess.run(["sh", "-n"], input=script, text=True).returncode, 0)
        st, _ = self.call("POST", "/api/ingest?agent=cloud-amd-1&token=yanlis", raw=b"#END", ctype="text/plain")
        self.assertEqual(st, 403)
        rep = "#HOST\ncloud-amd-1\n100.64.0.7\n#DOCKER\n#PORTS\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n#END\n"
        st, _ = self.call("POST", f"/api/ingest?agent=cloud-amd-1&token={token}", raw=rep.encode(), ctype="text/plain")
        self.assertEqual(st, 200)
        time.sleep(0.5)
        svcs = self.data()["ts:cloud-amd-1"]["services"]
        self.assertEqual([s["name"] for s in svcs], ["SSH"])
        st, _ = self.call("DELETE", "/api/agent?name=cloud-amd-1", {})
        self.assertEqual(st, 200)

    def test_scan_now(self):
        st, body = self.call("POST", "/api/scan", {})
        self.assertEqual(st, 200)


class ScriptsTest(unittest.TestCase):
    def test_installers_parse(self):
        for kind in ("router", "linux"):
            s = agents.installer(kind, "http://100.64.0.1:8088", "x", "tok")
            r = subprocess.run(["sh", "-n"], input=s, text=True, capture_output=True)
            self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(agents.topo_version(), "2")

    def test_router_installer_sandbox(self):
        """Router kurulum scriptini sahte kök dizinde BusyBox ile iki kez çalıştır."""
        bb = shutil.which("busybox")
        if not bb:
            self.skipTest("busybox yok")
        os.makedirs(os.path.join(ROOT, "tests", "out"), exist_ok=True)
        root = tempfile.mkdtemp(dir=os.path.join(ROOT, "tests", "out"))
        for d in ("usr/sbin", "etc/crontabs", "etc/dropbear", "etc/init.d", "tmp", "bin"):
            os.makedirs(os.path.join(root, d), exist_ok=True)
        with open(os.path.join(root, "etc/crontabs/root"), "w") as f:
            f.write("* * * * * /usr/sbin/ts-exit-watchdog\n17 4 * * 1 /usr/sbin/update-tailscale-safe")
        with open(os.path.join(root, "etc/dropbear/authorized_keys"), "w") as f:
            f.write("ssh-ed25519 AAAAexisting pi@laptop\n"
                    'command="/usr/sbin/topo-collect",no-pty ssh-ed25519 AAAAold topo@home-pi\n')
        # sahte curl: raporu dosyaya yazar
        with open(os.path.join(root, "bin/curl"), "w") as f:
            f.write(f"#!/bin/sh\necho called >> {root}/curl.log\nexit 0\n")
        os.chmod(os.path.join(root, "bin/curl"), 0o755)
        s = agents.installer("router", "http://100.64.0.1:8088", "router", "tok")
        for a, b in (("/usr/sbin/", f"{root}/usr/sbin/"), ("/etc/", f"{root}/etc/"), ("/tmp/", f"{root}/tmp/")):
            s = s.replace(a, b)
        env = {"PATH": f"{root}/bin:/usr/bin:/bin"}
        for _ in range(2):
            r = subprocess.run([bb, "sh", "-c", s], text=True, capture_output=True, env=env)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cron = open(os.path.join(root, "etc/crontabs/root")).read().splitlines()
        self.assertEqual(cron, ["* * * * * /usr/sbin/ts-exit-watchdog",
                                "17 4 * * 1 /usr/sbin/update-tailscale-safe",
                                f"*/5 * * * * {root}/usr/sbin/nodesk-agent"])
        ak = open(os.path.join(root, "etc/dropbear/authorized_keys")).read().splitlines()
        self.assertEqual(ak, ["ssh-ed25519 AAAAexisting pi@laptop"])
        self.assertEqual(open(os.path.join(root, "curl.log")).read().count("called"), 2)
        conf = open(os.path.join(root, "etc/nodesk-agent.conf")).read()
        self.assertIn("token=tok", conf)
        self.assertEqual(oct(os.stat(os.path.join(root, "etc/nodesk-agent.conf")).st_mode)[-3:], "600")
        shutil.rmtree(root)

    def test_cli_syntax(self):
        self.assertEqual(subprocess.run(["bash", "-n", os.path.join(ROOT, "bin", "nodesk")]).returncode, 0)


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


if __name__ == "__main__":
    unittest.main()
