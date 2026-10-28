"""Nodesk testleri: gerçek çıktılardan alınmış örneklerle (tests/fixtures).

    python3 -m unittest discover -s tests -v
"""

import datetime as dt
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
os.environ["NODESK_CONFIG"] = os.path.join(FIX, "config.toml")   # HomeNet benzeri örnek ağ

from nodesk import agents, history, model, passive, probe, server, sites, sources, store, util  # noqa: E402


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
        ag = next(a for a in self.data["agents"] if a["name"] == "router")
        self.assertEqual(ag["usage"], {"listen_rss_kb": 1504, "mem_available_kb": 131448}, "router'daki yük ölçülür")

    def test_linux_agent_services(self):
        arm = self.ids["ts:cloud-arm"]
        names = {s["name"]: s for s in arm["services"]}
        self.assertEqual(names["edge-caddy"]["ports"], [80, 443])
        self.assertEqual(names["edge-api"]["ports"], [], "127.0.0.1 portu dışarı açık sayılmaz")
        self.assertEqual(names["edge-caddy"]["app"], "edge")
        self.assertIn("SSH", names)
        self.assertTrue(arm["agent"]["fresh"])

    def test_service_nodes(self):
        orbis = self.ids["svc:self:media-app"]
        self.assertEqual(orbis["kind"], "service")
        self.assertEqual(orbis["parent"], "self")
        self.assertEqual(orbis["label"], "Orbis")
        self.assertEqual(sorted(c["name"] for c in orbis["containers"]), ["media-app-backend", "media-app-frontend"])
        self.assertEqual(orbis["ports"], [3000, 8000])
        self.assertEqual(orbis["health"], "partial", "8000 yanıt vermiyor (health.json)")
        gitea = self.ids["svc:self:gitea"]
        self.assertTrue(gitea["icon_url"].endswith("/Gitea/icon.png"), "CasaOS ikonu")
        self.assertEqual(gitea["health"], "ok")
        self.assertEqual(self.ids["svc:self:sys:smbd"]["glyph"], "folder")
        self.assertEqual(self.ids["svc:self:sys:sshd"]["glyph"], "terminal")
        self.assertIn("homarr-labs/dashboard-icons/png/casaos.png", self.ids["svc:self:sys:casaos-gateway"]["icon_url"])
        stopped = self.ids["svc:self:c:old-test"]
        self.assertEqual(stopped["state"], "exited")
        self.assertFalse(stopped["online"])
        self.assertEqual(self.ids["svc:ts:cloud-arm:edge"]["parent"], "ts:cloud-arm")

    def test_extender_clients_split(self):
        k = self.ids["mac:52:ff:20:53:86:18"]
        self.assertEqual(k["ips"], ["192.168.44.4"], "extender'ın sadece kendi IP'si")
        tab = self.ids["mac:d8:3a:dd:11:22:33"]
        self.assertEqual(tab["parent"], "mac:52:ff:20:53:86:18")
        self.assertEqual(tab["label"], "Galaxy-Tab-A")
        self.assertEqual(tab["kind"], "tablet")
        self.assertTrue(tab["online"])
        spk = self.ids["ip:192.168.44.9"]
        self.assertEqual(spk["parent"], "mac:52:ff:20:53:86:18")
        self.assertEqual(spk["label"], "Mutfak-Hoparlor")
        self.assertEqual(spk["kind"], "speaker")

    def test_roaming_device_moves_home(self):
        tuf = self.ids["ts:laptop"]
        self.assertEqual(tuf["site"], "ev1", "Tailscale'in bildirdiği yerel IP Ev 1'de canlı")
        self.assertEqual(tuf["parent"], "mac:6c:11:ba:f9:55:ab")
        self.assertIn("192.168.44.130", tuf["ips"])
        self.assertEqual(tuf["label"], "laptop")
        self.assertNotIn("mac:3c:7c:3f:12:34:56", self.ids, "aynı cihaz iki kez görünmez")
        self.assertEqual(self.ids["ts:nothing"]["site"], "mobile", "evde olmayan mobilde kalır")

    def test_router_name_queries(self):
        tv = self.ids["mac:1c:af:4a:55:4b:2c"]
        self.assertEqual(tv["names"]["mdns_services"], ["_airplay._tcp", "_spotify-connect._tcp"])
        self.assertEqual(tv["names"]["dhcp_name"], "Samsung")
        self.assertEqual(self.ids["mac:c0:49:43:1c:cc:12"]["names"]["nb_name"], "HGW")
        self.assertEqual(self.ids["mac:60:7e:a4:07:f9:d8"]["names"], {}, "bozuk satır atlanır")
        robo = self.ids["mac:b0:4a:39:74:6b:d6"]
        self.assertEqual(robo["names"]["dhcp_name"], "roborock-vacuum-a27", "router'ın duyduğu DHCP isteği")
        self.assertEqual(robo["kind"], "vacuum")

    def test_exit_node_links(self):
        links = {(o["from"], o["to"]) for o in self.data["overlay"]}
        self.assertIn(("router", "self"), links, "router'ın kendi seçimi")
        self.assertIn(("ts:nothing", "self"), links, "Pi'nin bağlantı tablosu: telefon Pi'den çıkıyor")
        self.assertEqual(self.ids["ts:nothing"]["exit_via"], "self")
        self.assertIn("ts:nothing", self.ids["self"]["exit_users"])
        self.assertIn(("ts:laptop", "router"), links, "router'ın bağlantı tablosu")
        self.assertNotIn(("router", "router"), links, "kendi trafiği sayılmaz")

    def test_exit_tuples_filter(self):
        e = [("100.64.0.3", "142.250.1.1", 6, 50000, 443),   # tailnet -> internet
             ("100.64.0.4", "192.168.1.1", 17, 5000, 53),     # yerel hedef: exit değil
             ("100.64.0.4", "100.64.0.1", 6, 5000, 22),   # tailnet içi
             ("192.168.44.8", "8.8.8.8", 17, 5000, 53)]           # tailnet dışı kaynak
        self.assertEqual(sources.exit_tuples(e), {e[0]})

    def test_exit_needs_new_connections(self):
        home = make_home()
        self.addCleanup(shutil.rmtree, home, True)
        app = server.App(home)
        app.fixtures = None   # canlı örnekleme mantığı
        samples = iter([{("100.64.0.3", "1.1.1.1", 6, 1, 443)},
                        {("100.64.0.3", "1.1.1.1", 6, 1, 443)},
                        {("100.64.0.3", "1.1.1.1", 6, 1, 443), ("100.64.0.3", "8.8.8.8", 17, 2, 53)}])
        orig = sources.exit_tuples_now
        sources.exit_tuples_now = lambda r: next(samples)
        try:
            src = {"tailscale": True}
            self.assertEqual(app.exit_clients(src), {}, "ilk örnek: karşılaştıracak önceki yok")
            self.assertEqual(app.exit_clients(src), {}, "eski bağlantı kalsa da yeni yok: exit kapalı")
            self.assertEqual(app.exit_clients(src), {"100.64.0.3": 1}, "yeni bağlantı: exit kullanılıyor")
        finally:
            sources.exit_tuples_now = orig

    def test_os_and_fallback_labels(self):
        self.assertEqual(model.os_guess({"dhcp_vendor": "android-dhcp-16"}), "Android 16")
        self.assertEqual(model.os_guess({"dhcp_vendor": "MSFT 5.0"}), "Windows")
        self.assertEqual(model.os_guess({"dhcp_fp": "1,121,3,6,15,108,114,119,252,95,44,46"}), "Apple")
        self.assertEqual(model.os_guess({"model": "iPhone15,2"}), "iOS")
        self.assertIsNone(model.os_guess({"dhcp_fp": "1,3,6,15"}))
        self.assertEqual(model.fallback_label(None, "62:ef:fd:53:b3:ae", "192.168.1.102",
                                              {"dhcp_vendor": "android-dhcp-16"}), "Android 16 (.102)")
        self.assertEqual(model.guess_type(None, "62:ef:fd:53:b3:ae", {"model": "AppleTV11,1"}), "tv")
        robo = self.ids["mac:b0:4a:39:74:6b:d6"]
        self.assertFalse(robo["unnamed"], "DHCP adı var")
        self.assertTrue(self.ids["mac:9c:8e:cd:01:02:03"]["unnamed"], "sadece üretici/IP biliniyor")

    def test_router_services(self):
        by = {n["label"]: n for n in self.data["nodes"] if n["kind"] == "service" and n["parent"] == "router"}
        self.assertEqual(by["LuCI"]["ports"], [80, 443])
        self.assertEqual(by["DNS"]["ports"], [53])
        self.assertEqual(by["SSH"]["ports"], [22])
        self.assertNotIn("Port 8009", by, "127.0.0.1 dinleyenler dışarıda")

    def test_sources_status(self):
        for k in ("tailscale", "arp", "neigh", "docker", "host_ports"):
            self.assertTrue(self.data["sources"][k]["ok"], k)


class DuplicateTest(unittest.TestCase):
    """27 Ekim'de Pi'den alınan gerçek veri: 3 Keenetic ve 2 LG TV görünüyordu."""
    T = "2026-10-27T18:26:00+00:00"
    PASSIVE = {
        "52:ff:20:53:86:18": {"ips": {"192.168.44.4": "2026-10-27T17:21:56+00:00",
                                      "192.168.44.7": "2026-10-27T17:21:56+00:00",
                                      "192.168.44.6": "2026-10-27T15:13:03+00:00",
                                      "192.168.44.14": "2026-10-27T18:26:26+00:00"},
                              "last": "2026-10-27T18:26:26+00:00", "mdns_name": "Keenetic-0000"},
        "38:8c:50:9f:be:1c": {"ips": {"192.168.44.11": "2026-10-27T18:26:15+00:00",
                                      "192.168.44.12": "2026-10-27T18:23:50+00:00"},
                              "last": "2026-10-27T18:26:15+00:00", "dhcp_name": "LGwebOSTV"},
        "b4:e6:2a:c2:32:4a": {"ips": {"192.168.44.12": "2026-10-27T15:50:55+00:00"},
                              "last": "2026-10-27T15:50:55+00:00", "dhcp_name": "LGwebOSTV"},
        "50:ff:20:73:86:18": {"ips": {"192.168.44.4": "2026-10-27T17:21:57+00:00",
                                      "192.168.44.14": "2026-10-27T17:23:09+00:00"},
                              "last": "2026-10-27T17:23:09+00:00", "dhcp_name": "Keenetic-0000"},
    }
    PASSIVE_IP = {
        "192.168.44.4": {"real_mac": "50:ff:20:73:86:18", "last": "2026-10-27T17:21:57+00:00"},
        "192.168.44.7": {"l2_mac": "52:ff:20:53:86:18", "last": "2026-10-27T17:21:56+00:00"},
        "192.168.44.11": {"real_mac": "38:8c:50:9f:be:1c", "l2_mac": "38:8c:50:9f:be:1c",
                          "dhcp_name": "LGwebOSTV", "last": "2026-10-27T18:26:15+00:00"},
        "192.168.44.12": {"real_mac": "b4:e6:2a:c2:32:4a", "l2_mac": "38:8c:50:9f:be:1c",
                          "dhcp_name": "LGwebOSTV", "last": "2026-10-27T18:23:50+00:00"},
        "192.168.44.14": {"real_mac": "50:ff:20:73:86:18", "l2_mac": "52:ff:20:53:86:18",
                          "dhcp_name": "Keenetic-0000", "mdns_name": "Keenetic-0000",
                          "last": "2026-10-27T18:26:26+00:00"},
    }
    ARP = [("192.168.44.11", "38:8c:50:9f:be:1c"), ("192.168.44.12", "38:8c:50:9f:be:1c"),
           ("192.168.44.14", "52:ff:20:53:86:18")]
    CFG = {"ev1": {"interface": "eth0"}, "devices": {
        "52:ff:20:53:86:18": {"name": "Keenetic-0000 extender", "type": "ap"},
        "70:54:b4:5a:b6:4e": {"name": "Toshiba TV", "type": "tv"},
        "b4:e6:2a:c2:32:4a": {"name": "LG TV 1", "type": "tv"},
        "38:8c:50:9f:be:1c": {"name": "LG TV 2", "type": "tv"}}}

    def build(self, state, cfg=None, extra_passive=None, extra_ip=None, extra_arp=(), overrides=None):
        raw = {"ifaces": [{"ifname": "eth0", "ip": "192.168.44.2", "prefix": 24, "mac": "88:a2:9e:35:f8:b1"}],
               "arp": [{"ip": ip, "mac": m, "vendor": None} for ip, m in [*self.ARP, *extra_arp]], "neigh": [],
               "passive": {**self.PASSIVE, **(extra_passive or {})},
               "passive_ip": {**self.PASSIVE_IP, **(extra_ip or {})}}
        settings = json.loads(json.dumps(store.DEFAULT_SETTINGS))
        settings["sources"]["router"] = False
        data, state = model.build(raw, cfg or self.CFG, settings, overrides or {"devices": {}}, state, {},
                                  util.parse_iso(self.T))
        return {n["id"]: n for n in data["nodes"]}, state

    def old_state(self):
        snap = lambda ips, **kw: {"first_seen": "2026-10-27T15:00:00+00:00",
                                  "last_seen": "2026-10-27T17:37:00+00:00",
                                  "snapshot": {"site": "ev1", "ips": ips, **kw}}
        return {"mac:50:ff:20:73:86:18": snap(["192.168.44.4"], mac="50:ff:20:73:86:18"),
                "ip:192.168.44.4": snap(["192.168.44.4"], parent_hint="mac:52:ff:20:53:86:18"),
                "ip:192.168.44.14": snap(["192.168.44.14"], parent_hint="mac:50:ff:20:73:86:18"),
                "mac:70:54:b4:5a:b6:4e": snap(["192.168.44.6"], mac="70:54:b4:5a:b6:4e")}

    def test_one_keenetic(self):
        ids, state = self.build(self.old_state())
        kn = [n for n in ids.values() if "keenetic" in (n["label"] + json.dumps(n.get("names"))).lower()]
        self.assertEqual([n["id"] for n in kn], ["mac:52:ff:20:53:86:18"])
        self.assertEqual(kn[0]["ips"], ["192.168.44.14"])
        self.assertEqual(kn[0]["aliases"], ["50:ff:20:73:86:18"])
        for gone in ("mac:50:ff:20:73:86:18", "ip:192.168.44.4", "ip:192.168.44.14"):
            self.assertNotIn(gone, ids)
            self.assertNotIn(gone, state, "eski kayıt da silinir, geri gelmez")

    def test_one_lg_tv(self):
        ids, _ = self.build({})
        tvs = [n for n in ids.values() if n.get("names", {}).get("dhcp_name") == "LGwebOSTV"]
        self.assertEqual(len(tvs), 1)
        self.assertEqual(tvs[0]["ips"], ["192.168.44.11", "192.168.44.12"])
        self.assertEqual(tvs[0]["aliases"], ["b4:e6:2a:c2:32:4a"])
        self.assertTrue(tvs[0]["online"])

    def test_extender_ip_keeps_last_owner(self):
        ids, _ = self.build(self.old_state())
        self.assertNotIn("ip:192.168.44.6", ids)
        self.assertEqual(ids["mac:70:54:b4:5a:b6:4e"]["parent"], "mac:52:ff:20:53:86:18")

    # Aynı S24: F1611A Wi-Fi'ında a6:8e.., Keenetic Wi-Fi'ında d2:61.. (Android'in ağ başına MAC'i)
    S24_P = {"a6:8e:da:14:ea:d0": {"ips": {"192.168.44.8": "2026-10-27T18:00:00+00:00"},
                                   "last": "2026-10-27T18:00:00+00:00", "mdns_name": "Android_IZKLG79Q"},
             "d2:61:e5:6d:9a:c3": {"ips": {"192.168.44.10": "2026-10-27T18:20:00+00:00"},
                                   "last": "2026-10-27T18:20:00+00:00", "dhcp_name": "Ali-adli-kisiye-ait-S24"}}
    S24_IP = {"192.168.44.10": {"real_mac": "d2:61:e5:6d:9a:c3", "l2_mac": "52:ff:20:53:86:18",
                                "last": "2026-10-27T18:20:00+00:00"}}
    S24_STATE = {"mac:a6:8e:da:14:ea:d0": {"first_seen": "2026-10-27T14:00:00+00:00",
                                           "last_seen": "2026-10-27T18:10:00+00:00",
                                           "snapshot": {"mac": "a6:8e:da:14:ea:d0", "site": "ev1",
                                                        "ips": ["192.168.44.8"]}}}

    def s24(self, cfg=None, overrides=None):
        return self.build(json.loads(json.dumps(self.S24_STATE)), cfg, self.S24_P, self.S24_IP,
                          [("192.168.44.10", "52:ff:20:53:86:18")], overrides)

    def test_phone_on_two_wifis_by_config_name(self):
        cfg = {**self.CFG, "devices": {**self.CFG["devices"], "a6:8e:da:14:ea:d0": {"name": "S24"},
                                       "d2:61:e5:6d:9a:c3": {"name": "S24"}}}
        ids, _ = self.s24(cfg, {"devices": {"mac:a6:8e:da:14:ea:d0": {"name": "S24 Ali"}}})
        s24 = [n for n in ids.values() if n["label"].startswith("S24")]
        self.assertEqual([n["id"] for n in s24], ["mac:a6:8e:da:14:ea:d0"], "kimlik düzenlenen MAC'te kalır")
        self.assertEqual(s24[0]["label"], "S24 Ali")
        self.assertEqual(s24[0]["mac"], "d2:61:e5:6d:9a:c3", "adres ve konum şu anki MAC'ten")
        self.assertEqual(s24[0]["aliases"], ["a6:8e:da:14:ea:d0"])
        self.assertEqual(s24[0]["parent"], "mac:52:ff:20:53:86:18")
        self.assertTrue(s24[0]["online"])

    def test_phone_hint_and_manual_merge(self):
        ids, _ = self.s24()
        self.assertEqual(ids["mac:d2:61:e5:6d:9a:c3"]["same_hint"]["id"], "mac:a6:8e:da:14:ea:d0",
                         "biri kayboldu, diğeri hemen geldi: öneri")
        ids, _ = self.s24(overrides={"devices": {"mac:d2:61:e5:6d:9a:c3": {"same_as": "mac:a6:8e:da:14:ea:d0"}}})
        self.assertNotIn("mac:a6:8e:da:14:ea:d0", ids)
        self.assertTrue(ids["mac:d2:61:e5:6d:9a:c3"]["online"])
        ids, _ = self.s24(overrides={"devices": {"mac:d2:61:e5:6d:9a:c3": {"not_same": "mac:a6:8e:da:14:ea:d0"}}})
        self.assertNotIn("same_hint", ids["mac:d2:61:e5:6d:9a:c3"], "reddedilen öneri tekrar gelmez")

    def test_same_dhcp_name_merge_and_apart_memory(self):
        snap = lambda mac, name: {"snapshot": {"mac": mac, "names": {"dhcp_name": name}}}
        A, B = "mac:02:00:00:00:00:01", "mac:02:00:00:00:00:02"
        state = {A: snap(A[4:], "Ali-adli-kisiye-ait-S24"), B: snap(B[4:], "Ali-adli-kisiye-ait-S24")}
        self.assertEqual(model.same_device_groups(state, lambda n: n == A, {}, {}), ([[A, B]], []))
        self.assertEqual(model.same_device_groups(state, lambda n: True, {}, {}), ([], [(A, B)]),
                         "aynı ARP taramasında ikisi birden: iki ayrı cihaz")
        state[A]["apart"] = [B]
        self.assertEqual(model.same_device_groups(state, lambda n: False, {}, {}), ([], []),
                         "bir kez ayrı görülen bir daha adla birleşmez")

    def test_factory_names_never_merge(self):
        snap = lambda mac, name: {"snapshot": {"mac": mac, "names": {"dhcp_name": name}}}
        for name in ("Galaxy-S24", "iPhone", "Redmi-Note-12", "Pixel-8", "SM-S921B"):
            state = {"mac:02:00:00:00:00:01": snap("02:00:00:00:00:01", name),
                     "mac:02:00:00:00:00:02": snap("02:00:00:00:00:02", name)}
            self.assertEqual(model.same_device_groups(state, lambda n: False, {}, {}), ([], []), name)
        self.assertFalse(model.is_generic_name("android-1a2b3c4d5e6f7a8b"), "cihaza özgü kimlik")
        self.assertFalse(model.is_generic_name("Ali-adli-kisiye-ait-S24"))

    def test_different_names_not_merged(self):
        self.assertFalse(model.twin_mac("50:ff:20:73:86:18", "50:ff:20:11:22:33"), "iki ayrı Keenetic")
        self.assertTrue(model.twin_mac("50:ff:20:73:86:18", "52:ff:20:53:86:18"))


class ProbeTest(unittest.TestCase):
    def name(self, n):
        return probe.qname(n)

    def test_nbstat(self):
        q = probe.nbstat_query(7)
        self.assertEqual(len(q), 50)
        entries = b"WORKGROUP      \x00\x84\x00" + b"DESKTOP-K7Q2   \x00\x04\x00"
        rdata = bytes([2]) + entries + b"\0" * 46
        resp = (struct.pack("!HHHHHH", 7, 0x8400, 0, 1, 0, 0) + q[12:12 + 34]
                + struct.pack("!HHIH", 0x21, 1, 0, len(rdata)) + rdata)
        self.assertEqual(probe.parse_nbstat(resp), "DESKTOP-K7Q2", "grup adı atlanır")

    def test_mdns_reverse_and_services(self):
        q = probe.mdns_query("192.168.44.7", 3)
        self.assertIn(self.name("7.44.168.192.in-addr.arpa"), q)
        ptr = lambda owner, target: (self.name(owner) + struct.pack("!HHIH", 12, 1, 120, len(self.name(target)))
                                     + self.name(target))
        resp = (struct.pack("!HHHHHH", 3, 0x8400, 0, 2, 0, 0)
                + ptr("7.44.168.192.in-addr.arpa", "Salon-TV.local")
                + ptr("_services._dns-sd._udp.local", "_googlecast._tcp.local"))
        obs = passive.mdns_obs(resp, {"ip": "192.168.44.7"})
        self.assertEqual(obs["mdns_name"], "Salon-TV")
        self.assertEqual(obs["mdns_services"], ["_googlecast._tcp"])

    def test_apple_companion_link(self):
        q = probe.mdns_services_query(0)
        self.assertIn(self.name("_companion-link._tcp.local"), q)
        inst = "Ali\u2019s iPhone._companion-link._tcp.local"
        txt = b"".join(bytes([len(x)]) + x for x in (b"rpMd=iPhone15,2", b"rpVr=510.2"))
        resp = (struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 1)
                + self.name("_companion-link._tcp.local") + struct.pack("!HHIH", 12, 1, 120, len(self.name(inst)))
                + self.name(inst)
                + self.name(inst) + struct.pack("!HHIH", 16, 1, 120, len(txt)) + txt)
        found = {"mac": "02:00:00:00:00:09", "ip": "192.168.44.30", "via": "probe"}
        probe.merge_obs(found, passive.mdns_obs(resp, {"ip": "192.168.44.30"}))
        probe.merge_obs(found, {"mdns_services": ["_airplay._tcp"]})
        self.assertEqual(found["model"], "iPhone15,2")
        self.assertEqual(found["mdns_instances"], ["Ali\u2019s iPhone"])
        self.assertEqual(found["mdns_services"], ["_airplay._tcp", "_companion-link._tcp"], "yanıtlar birikir")
        self.assertEqual(found["mac"], "02:00:00:00:00:09")

    def test_upnp_fields(self):
        xml = "<root><device><friendlyName>[LG] webOS TV &amp; Salon</friendlyName><modelName>OLED55</modelName>"
        self.assertEqual(probe.xml_tag(xml, "friendlyName"), "[LG] webOS TV & Salon")
        self.assertIsNone(probe.xml_tag(xml, "manufacturer"))
        self.assertEqual(probe.ssdp_location(b"HTTP/1.1 200 OK\r\nLocation: http://192.168.44.11:1880/\r\n\r\n"),
                         "http://192.168.44.11:1880/")
        self.assertEqual(probe.upnp_description("http://10.0.0.9/x.xml", "192.168.44.11"), {},
                         "başka adrese gitmez")


class GenericSitesTest(unittest.TestCase):
    """config.toml'da hiçbir ağ bilgisi yokken: her şey kendiliğinden bulunur."""

    def test_router_agent_becomes_site(self):
        rd = lambda name: open(os.path.join(FIX, name), encoding="utf-8").read()
        raw = {"ts": json.loads(rd("tailscale.json")), "hostname": "pi5",
               "ifaces": [{"ifname": "eth0", "ip": "10.0.0.2", "prefix": 24, "mac": "88:a2:9e:35:f8:b1"}],
               "route": {"dev": "eth0", "gateway": "10.0.0.1"},
               "arp": [{"ip": "10.0.0.1", "mac": "6c:11:ba:f9:55:ab", "vendor": None}], "neigh": [],
               "reports": {"evim": {"kind": "router", "received": NOW, "sections": util.parse_sections(rd("router.txt"))}}}
        settings = json.loads(json.dumps(store.DEFAULT_SETTINGS))
        allsites = sites.resolve(None, ["evim"])
        data, _ = model.build(raw, {}, settings, {"devices": {}}, {}, {}, util.parse_iso(NOW), {"sites": allsites})
        ids = {n["id"]: n for n in data["nodes"]}
        self.assertEqual([x["id"] for x in data["sites"]][:2], ["ev1", "evim"])
        self.assertEqual(ids["self"]["label"], "pi5", "Pi'nin adı host adından")
        self.assertEqual(ids["mac:6c:11:ba:f9:55:ab"]["kind"], "modem", "yerel geçit varsayılan rotadan")
        r = ids["router:evim"]
        self.assertEqual(r["site"], "evim")
        self.assertEqual(r["parent"], "mac:c0:49:43:1c:cc:12", "modem router'ın varsayılan rotasından")
        self.assertEqual(ids["mac:c0:49:43:1c:cc:12"]["kind"], "modem")
        self.assertEqual(ids["mac:1c:af:4a:55:4b:2c"]["parent"], "router:evim")
        self.assertEqual(r["tailscale"]["name"], "home-router", "Tailscale adı raporundaki tailscale0'dan")
        self.assertNotIn("ts:home-router", ids, "router iki kez görünmez")
        self.assertEqual(ids["ts:cloud-arm"]["site"], "mobile", "atanmamış Tailscale cihazı varsayılan grupta")

    def test_migration_and_validation(self):
        cfg = {"ev1": {"name": "Ana ev", "gateway_ip": "192.168.44.1"}, "ev2": {"modem_ip": "192.168.1.1"},
               "oracle": {"name": "Bulut"}, "tailscale": {"site_of": {"Cloud-Arm": "oracle"}}}
        ss, ts_site = sites.from_config(cfg)
        self.assertEqual([x["id"] for x in ss], ["ev1", "ev2", "oracle", "mobile"])
        self.assertEqual(ss[1]["agent"], "router")
        self.assertEqual(ts_site, {"cloud-arm": "oracle"})
        self.assertEqual(len(sites.resolve(ss, ["router"])), 4, "ajanı zaten grubu olan router eklenmez")
        with self.assertRaises(ValueError):
            sites.validate([{"id": "a", "type": "group"}])                 # yerel ağ yok
        with self.assertRaises(ValueError):
            sites.validate([{"id": "ev1", "type": "local"}, {"id": "ev1", "type": "group"}])
        with self.assertRaises(ValueError):
            sites.validate([{"id": "ev1", "type": "local"}, {"id": "../x", "type": "group"}])
        ok = sites.validate([{"id": "ev1", "type": "local", "name": "Ev", "evil": 1},
                             {"id": "bulut", "type": "group", "kind": "cloud"}])
        self.assertNotIn("evil", ok[0])


class HistoryAlertsTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def test_history_percent(self):
        h = history.History(os.path.join(self.d, "h.json"))
        t0 = util.parse_iso("2026-10-28T00:00:00+00:00")
        for i in range(12):   # 2 saat, her 10 dakikada bir; ilk saat çevrimiçi
            h.record([{"id": "mac:a", "kind": "phone", "online": i < 6}], t0 + dt.timedelta(minutes=10 * i))
        sm = h.summary("mac:a", t0 + dt.timedelta(minutes=110))
        self.assertEqual(sm["pct"], 50)
        self.assertEqual(list(sm["days"]), ["2026-10-28"])
        self.assertIsNone(h.summary("mac:yok", t0))
        h2 = history.History(os.path.join(self.d, "h2.json"))
        h2.record([{"id": "mac:b", "kind": "phone", "online": True}], t0 + dt.timedelta(hours=10))
        self.assertEqual(h2.summary("mac:b", t0 + dt.timedelta(hours=10, minutes=5))["pct"], 100,
                         "yeni cihaz: gece yarısından değil ilk kaydından say")

    def test_notifier_transitions(self):
        n = history.Notifier(os.path.join(self.d, "a.json"))
        dev = lambda i, **k: {"id": i, "kind": "phone", "label": i, "ips": ["10.0.0.9"], **k}
        svc = lambda i, on: {"id": i, "kind": "service", "label": i, "online": on, "host": "self"}
        base = {"nodes": [dev("mac:a"), svc("svc:self:gitea", True)], "agents": [{"name": "router", "fresh": True}],
                "overlay": []}
        self.assertEqual(n.check(base, {}), [], "ilk çalışmada yalnızca öğrenir")
        nxt = {"nodes": [dev("mac:a"), dev("mac:yeni"), dev("ip:10.0.0.7"), svc("svc:self:gitea", False)],
               "agents": [{"name": "router", "fresh": False}], "overlay": [{"from": "mac:a", "to": "self"}]}
        titles = sorted(t for t, _, _ in n.check(nxt, {}))
        self.assertEqual(titles, ["Ajan sustu", "Exit node değişti", "Servis kapandı", "Yeni cihaz"],
                         "geçici ip: kimliği yeni cihaz sayılmaz")
        self.assertEqual(n.check(nxt, {}), [], "değişmeyen durum tekrar bildirilmez")

    def test_secrets_never_public(self):
        home = make_home()
        self.addCleanup(shutil.rmtree, home, True)
        st = store.Store(store.Paths(home))
        st.set_settings({"alerts": {"ntfy_url": "https://ntfy.sh/gizli-konu", "telegram_token": "123456:" + "A" * 30,
                                    "telegram_chat": "-100123"}})
        app = server.App(home, FIX)
        app.collect()
        with open(os.path.join(home, "www", "data.json"), encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn("gizli-konu", text)
        self.assertNotIn("AAAAAAAAAA", text)
        for bad in ({"ntfy_url": "ftp://x"}, {"telegram_token": "kötü"}, {"telegram_chat": "x y"}):
            with self.assertRaises(ValueError):
                st.set_settings({"alerts": bad})


class FileSafetyTest(unittest.TestCase):
    def test_corrupt_json_uses_backup(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "overrides.json")
        util.write_json(p, {"devices": {"a": 1}})
        util.write_json(p, {"devices": {"a": 2}})          # önceki sürüm .bak'ta
        with open(p, "w") as f:
            f.write('{"devices": {"a": 3')                   # yarım yazılmış dosya
        self.assertEqual(util.read_json(p, {}), {"devices": {"a": 1}}, "son sağlam yedek")
        self.assertTrue(any(x.startswith("overrides.json.bozuk-") for x in os.listdir(d)), "bozuk dosya kenarda")
        self.assertEqual(util.read_json(p, {}), {"devices": {"a": 1}}, "geri yüklendi")


class CasaosTitleTest(unittest.TestCase):
    def test_pathological_compose_is_fast(self):
        """0.2.0'da regex bu biçimde dakikalarca takılıp tüm servisi kilitliyordu."""
        body = "\n".join(f"        key{i}: value" for i in range(400))
        text = "name: media-app\nservices:\n  web:\n    image: x\nx-casaos:\n" + body + "\n    title: plain\n"
        t0 = time.monotonic()
        sources.casaos_title(text)
        self.assertLess(time.monotonic() - t0, 0.2)

    def test_forms(self):
        f = sources.casaos_title
        self.assertEqual(f("x-casaos:\n  main: web\n  title:\n    en_us: Gitea\n"), "Gitea")
        self.assertEqual(f("x-casaos:\n  title:\n    en_us: media-app\n    custom: Orbis\n"), "Orbis")
        self.assertEqual(f("x-casaos:\n  title: 'Düz Başlık'\n"), "Düz Başlık")
        self.assertIsNone(f("services:\n  web:\n    x-casaos:\n      title:\n        en_us: İçteki\n"))
        self.assertIsNone(f("x-casaos:\n  tips:\n    title:\n      en_us: Derindeki\n"))
        self.assertEqual(f("services:\n  a:\n    x-casaos:\n      title:\n        en_us: İç\nx-casaos:\n  title:\n    en_US: Dış\n"), "Dış")
        self.assertIsNone(f(""))


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
    def call(cls, method, path, body=None, ctype="application/json", raw=None, headers=None, full=False):
        data = raw if raw is not None else (json.dumps(body or {}).encode() if method != "GET" else None)
        req = urllib.request.Request(f"http://127.0.0.1:{cls.port}{path}", data=data, method=method,
                                     headers={"Content-Type": ctype, **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return (r.status, r.read().decode(), r.headers) if full else (r.status, r.read().decode())
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

    def test_card_colors(self):
        st, body = self.call("PUT", "/api/settings", {"colors": {"net": "#AABBCC", "other": ""}})
        self.assertEqual(st, 200)
        colors = json.loads(body)["colors"]
        self.assertEqual(colors["net"], "#aabbcc")
        self.assertEqual(colors["other"], "", "renksiz")
        self.assertEqual(colors["srv"], store.DEFAULT_SETTINGS["colors"]["srv"], "değiştirilmeyen varsayılanda")
        for bad in ({"net": "red"}, {"net": "#12345"}, {"uzay": "#112233"}, {"net": "#112233;x"}):
            st, _ = self.call("PUT", "/api/settings", {"colors": bad})
            self.assertEqual(st, 400, bad)
        self.call("PUT", "/api/settings", {"colors": store.DEFAULT_SETTINGS["colors"]})

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

    def test_ingest_asks_old_agent_to_update(self):
        token = store.Store(store.Paths(self.home)).agents()["agents"]["router"]["token"]
        old = open(os.path.join(FIX, "router.txt")).read().replace("#VERSION\n10", "#VERSION\n2", 1)
        st, body = self.call("POST", f"/api/ingest?agent=router&token={token}", raw=old.encode(), ctype="text/plain")
        self.assertEqual((st, body.strip()), (200, "ok update"))
        cur = open(os.path.join(FIX, "router.txt")).read()
        st, body = self.call("POST", f"/api/ingest?agent=router&token={token}", raw=cur.encode(), ctype="text/plain")
        self.assertEqual((st, body.strip()), (200, "ok"))

    def test_service_override(self):
        st, _ = self.call("PUT", "/api/device?id=svc:self:media-app", {"name": "Orbis Medya", "icon": "https://ornek.com/o.png"})
        self.assertEqual(st, 200)
        n = self.data()["svc:self:media-app"]
        self.assertEqual(n["label"], "Orbis Medya")
        self.assertEqual(n["icon_url"], "https://ornek.com/o.png")
        st, _ = self.call("PUT", "/api/device?id=svc:self:media-app", {"icon": "javascript:alert(1)"})
        self.assertEqual(st, 400)
        self.call("PUT", "/api/device?id=svc:self:media-app", {})

    def test_rename_site_and_root(self):
        st, _ = self.call("PUT", "/api/site?id=ev1", {"name": "Ana ev"})
        self.assertEqual(st, 200)
        st, _ = self.call("PUT", "/api/device?id=oracle-gw", {"name": "Frankfurt"})
        self.assertEqual(st, 200)
        with open(os.path.join(self.home, "www", "data.json"), encoding="utf-8") as f:
            d = json.load(f)
        self.assertEqual(next(x for x in d["sites"] if x["id"] == "ev1")["name"], "Ana ev")
        self.assertEqual(next(n for n in d["nodes"] if n["id"] == "oracle-gw")["label"], "Frankfurt")
        st, _ = self.call("PUT", "/api/site?id=uzay", {"name": "x"})
        self.assertEqual(st, 400)
        self.call("PUT", "/api/site?id=ev1", {})
        self.call("PUT", "/api/device?id=oracle-gw", {})

    def test_access_rules(self):
        """Ev ağı (misafir) görür ama düzenleyemez; tailnet düzenler; hesap listesi ve parola."""
        app = server.Handler.app
        lan, ts = {"X-Real-IP": "192.168.44.50"}, {"X-Real-IP": "100.64.0.4"}
        dev = "/api/device?id=mac:9c:8e:cd:01:02:03"
        self.assertEqual(self.call("GET", "/api/state", headers=lan)[0], 200, "harita herkese açık")
        self.assertEqual(self.call("GET", "/api/data", headers=lan)[0], 200)
        self.assertEqual(self.call("PUT", dev, {"name": "x"}, headers=lan)[0], 401, "misafir düzenleyemez")
        self.assertEqual(self.call("GET", "/api/agents", headers=lan)[0], 401, "ajan anahtarları gizli")
        self.assertEqual(self.call("POST", "/api/scan", {}, headers=lan)[0], 401)
        self.assertEqual(self.call("PUT", dev, {"name": "x"}, headers=ts)[0], 200, "tailnet düzenler")
        self.assertNotIn("alerts", json.loads(self.call("GET", "/api/state", headers=lan)[1])["settings"],
                         "bildirim anahtarları misafire gitmez")
        a = json.loads(self.call("GET", "/api/auth", headers=lan)[1])
        self.assertEqual((a["edit"], a["view"], a["access"]), (False, True, None))
        # yalnızca belirli Tailscale hesapları (kimlik whois ile, istemciye sorulmaz)
        app.auth._whois_cache.clear()
        app.auth._whois = lambda ip: {"100.64.0.4": "sahip@ornek.com"}.get(ip)
        self.call("PUT", "/api/settings", {"access": {"ts_users": ["Sahip@ornek.com"]}})
        self.assertEqual(self.call("PUT", dev, {"name": "x"}, headers=ts)[0], 200)
        self.assertEqual(self.call("PUT", dev, {"name": "x"}, headers={"X-Real-IP": "100.64.0.3"})[0], 401,
                         "listede olmayan tailnet hesabı")
        # parola: ev ağından giriş
        app.auth.set_password("dogru-parola-1")
        self.assertEqual(self.call("POST", "/api/login", {"password": "yanlis"}, headers=lan)[0], 403)
        st, _, h = self.call("POST", "/api/login", {"password": "dogru-parola-1"}, headers=lan, full=True)
        self.assertEqual(st, 200)
        cookie = h["Set-Cookie"].split(";")[0]
        self.assertIn("HttpOnly", h["Set-Cookie"])
        self.assertEqual(self.call("PUT", dev, {"name": "x"}, headers={**lan, "Cookie": cookie})[0], 200)
        self.call("POST", "/api/logout", {}, headers={**lan, "Cookie": cookie})
        self.assertEqual(self.call("PUT", dev, {"name": "x"}, headers={**lan, "Cookie": cookie})[0], 401,
                         "çıkıştan sonra oturum geçersiz")
        # gizli harita: görmek için de giriş; data.json herkese açık klasörde kalmaz
        self.call("PUT", "/api/settings", {"access": {"view": "login", "ts_users": []}})
        self.assertEqual(self.call("GET", "/api/data", headers=lan)[0], 401)
        self.assertFalse(os.path.exists(os.path.join(self.home, "www", "data.json")))
        self.assertEqual(self.call("GET", "/api/data", headers=ts)[0], 200)
        self.call("PUT", "/api/settings", {"access": {"view": "everyone"}})
        self.assertTrue(os.path.exists(os.path.join(self.home, "www", "data.json")))
        self.call("PUT", dev, {})
        os.remove(app.paths.auth)

    def test_scan_now(self):
        st, body = self.call("POST", "/api/scan", {})
        self.assertEqual(st, 200)


class ScriptsTest(unittest.TestCase):
    def test_installers_parse(self):
        for kind in ("router", "linux"):
            s = agents.installer(kind, "http://100.64.0.1:8088", "x", "tok")
            r = subprocess.run(["sh", "-n"], input=s, text=True, capture_output=True)
            self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(agents.topo_version(), "10")

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

    def test_router_agent_self_update(self):
        """Pi "ok update" derse ajan kurulum scriptini Pi'den alıp çalıştırır; kapalıysa çalıştırmaz."""
        bb = shutil.which("busybox")
        if not bb:
            self.skipTest("busybox yok")
        os.makedirs(os.path.join(ROOT, "tests", "out"), exist_ok=True)
        root = tempfile.mkdtemp(dir=os.path.join(ROOT, "tests", "out"))
        for d in ("usr/sbin", "etc", "tmp", "bin"):
            os.makedirs(os.path.join(root, d), exist_ok=True)
        s = agents.installer("router", "http://pi:8088", "router", "tok")
        agent = s.split("cat > /usr/sbin/nodesk-agent.new <<'NODESK_EOF'\n", 1)[1].split("\nNODESK_EOF", 1)[0]
        for a, b in (("/usr/sbin/", f"{root}/usr/sbin/"), ("/etc/", f"{root}/etc/"), ("/tmp/", f"{root}/tmp/")):
            agent = agent.replace(a, b)
        with open(f"{root}/usr/sbin/nodesk-agent", "w") as f:
            f.write(agent)
        with open(f"{root}/usr/sbin/topo-collect", "w") as f:
            f.write("#!/bin/sh\necho '#VERSION'\necho 2\necho '#END'\n")
        os.chmod(f"{root}/usr/sbin/topo-collect", 0o755)
        with open(f"{root}/etc/nodesk-agent.conf", "w") as f:
            f.write("NODESK_URL='http://pi/ingest'\nNODESK_INSTALL_URL='http://pi/install'\n")
        # sahte curl: POST'a "ok update" der, GET'te marker dosyası oluşturan bir kurulum scripti verir
        with open(f"{root}/bin/curl", "w") as f:
            f.write(f"""#!/bin/sh
o=""; post=""
while [ $# -gt 0 ]; do case "$1" in -o) o="$2"; shift;; --data-binary) post=1;; esac; shift; done
if [ -n "$post" ]; then printf '%s\\n' "$(cat {root}/answer)" > "$o"
else printf '#!/bin/sh\\n# NODESK_EOF\\ntouch {root}/updated\\n' > "$o"; fi
""")
        os.chmod(f"{root}/bin/curl", 0o755)
        env = {"PATH": f"{root}/bin:/usr/bin:/bin"}
        for answer, expect in (("ok", False), ("ok update", True)):
            open(f"{root}/answer", "w").write(answer)
            r = subprocess.run([bb, "sh", f"{root}/usr/sbin/nodesk-agent"], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(os.path.exists(f"{root}/updated"), expect, answer)
        os.unlink(f"{root}/updated")
        r = subprocess.run([bb, "sh", f"{root}/usr/sbin/nodesk-agent"], env={**env, "NODESK_UPDATING": "1"})
        self.assertFalse(os.path.exists(f"{root}/updated"), "kurulum sırasında tekrar güncellemeye girmez")
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
