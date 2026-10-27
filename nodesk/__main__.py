"""python3 -m nodesk <komut>

  serve                  sunucuyu çalıştır (systemd)
  collect                tek seferlik toplama (test / elle)
  agent-script <ad>      ajan kurulum scriptini yazdır (gerekirse ajanı oluşturur)
  agent-add <ad> [tür]   ajan oluştur (tür: linux | router), kurulum komutunu yazdır
  agent-remove <ad>      ajanı sil
  agent-list             ajanları listele
"""

import os
import sys

from . import agents, server, store


def main(argv):
    home = os.environ.get("NODESK_HOME", "/DATA/AppData/nodesk")
    fixtures = os.environ.get("NODESK_FIXTURES")
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "serve":
        server.serve(home, fixtures)
        return 0
    if cmd == "collect":
        return server.collect_once(home, fixtures)
    if cmd in ("agent-script", "agent-add", "agent-remove", "agent-list"):
        app = server.App(home, fixtures)
        app.raw = {"ts": None}
        st = app.store
        if cmd == "agent-list":
            for name, a in sorted(st.agents()["agents"].items()):
                rep = st.reports().get(name, {})
                print(f"{name:20} {a['kind']:7} son rapor: {rep.get('received') or 'yok'}")
            return 0
        if len(argv) < 3:
            print(__doc__, file=sys.stderr)
            return 2
        name = argv[2]
        if cmd == "agent-remove":
            print("silindi" if st.remove_agent(name) else "böyle bir ajan yok")
            return 0
        kind = argv[3] if len(argv) > 3 else ("router" if name == "router" else "linux")
        a = st.add_agent(name, kind)
        base = os.environ.get("NODESK_PUBLIC_URL") or app.public_url()
        if cmd == "agent-script":
            sys.stdout.write(agents.installer(a["kind"], base, name, a["token"]))
        else:
            for where, c in agents.install_commands(a["kind"], base, name, a["token"]).items():
                print(f"{where}: {c}")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
