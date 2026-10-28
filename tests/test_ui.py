"""Arayüz denetimi: örnek verilerle önizleme sunucusu + başsız Chromium.

Haritanın kendi öz-testi (index.html, #selftest) kartların üst üste binmediğini, exit ve Tailnet
çizgilerinin kartların içinden geçmediğini ve JS hatası olmadığını birkaç ekran boyutunda denetler.
Chromium yoksa atlanır.
"""

import html
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import unittest
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BROWSER = next((b for b in ("chromium", "chromium-browser", "google-chrome") if shutil.which(b)), None)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@unittest.skipUnless(BROWSER, "Chromium yok")
class UiSelfTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = free_port()
        env = {**os.environ, "PREVIEW_PORT": str(cls.port), "NODESK_API_PORT": str(free_port())}
        cls.proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "tests", "preview.py")], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{cls.port}/api/data", timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(10)

    def run_selftest(self, size, lang="en"):
        out = subprocess.run([BROWSER, "--headless", "--disable-gpu", f"--window-size={size}",
                              "--virtual-time-budget=9000", "--dump-dom",
                              f"http://127.0.0.1:{self.port}/?lang={lang}#selftest"],
                             capture_output=True, text=True, timeout=90).stdout
        m = out.split('data-selftest="', 1)
        self.assertEqual(len(m), 2, f"öz-test sonucu yok ({size})")
        self.assertIn(f'<html lang="{lang}"', out)
        return json.loads(html.unescape(m[1].split('"', 1)[0]))

    def test_layout_and_lines(self):
        for size, lang in (("1920,1080", "en"), ("1366,768", "en"), ("1100,1300", "en"), ("520,900", "en"), ("1366,768", "tr")):
            r = self.run_selftest(size, lang)
            self.assertTrue(r["ok"], f"{size}: {r['problems']} {r['errors']}")
            self.assertGreater(r["cards"], 20, size)
            self.assertGreaterEqual(r["lines"], 3, f"{size}: örnek verideki exit çizgileri çizilmeli")


if __name__ == "__main__":
    unittest.main()
