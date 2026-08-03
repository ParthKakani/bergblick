"""
Attacker driver.

Every attack here makes **real HTTP requests to the shop's own routes**, from a background
thread, using the same endpoints a browser uses. The SOC sees them because they are genuine
requests that the shop logs — not because the attack told the SOC anything.

This is what makes the demo a real-world one: the control panel presses a button, the
driver hammers the live site, and detection fires off the resulting access log.
"""

import random
import threading
import time

import requests

from .data import BREACH_CORPUS


class Attacker:
    def __init__(self, base_url):
        self.base = base_url.rstrip("/")
        self._running = {}

    def _post(self, path, **kw):
        try:
            return requests.post(self.base + path, timeout=2, **kw)
        except Exception:
            return None

    def _get(self, path, **kw):
        try:
            return requests.get(self.base + path, timeout=2, **kw)
        except Exception:
            return None

    # ------------------------------------------------------------------
    # R-02 — credential stuffing: replay a breach corpus at the login route
    # ------------------------------------------------------------------
    def credential_stuffing(self, rounds=40):
        def run():
            for _ in range(rounds):
                email, pw = random.choice(BREACH_CORPUS)
                ip = f"185.{random.randint(2,254)}.{random.randint(2,254)}.{random.randint(2,254)}"
                self._post("/api/login",
                           json={"email": email, "password": pw, "attack": True},
                           headers={"X-Forwarded-For": ip})
                time.sleep(0.06)
        threading.Thread(target=run, daemon=True).start()
        return f"Replaying {rounds} breached credentials from a proxy pool"

    # ------------------------------------------------------------------
    # R-05 — card testing, crude (one session, many attempts)
    # ------------------------------------------------------------------
    def card_testing_crude(self, attempts=25):
        def run():
            sess = "atk-" + str(random.randint(1000, 9999))
            for i in range(attempts):
                self._post("/api/checkout",
                           json={"session": sess, "card": f"4111{i:012d}",
                                 "value": 1, "method": "card", "attack": True,
                                 "expect": "fail"})
                time.sleep(0.05)
        threading.Thread(target=run, daemon=True).start()
        return f"{attempts} authorisation attempts from a single session"

    # ------------------------------------------------------------------
    # R-05 — card testing, distributed (one attempt per session)
    # ------------------------------------------------------------------
    def card_testing_distributed(self, attempts=40):
        def run():
            for i in range(attempts):
                sess = "d-" + str(random.randint(10000, 99999))
                ip = f"92.{random.randint(2,254)}.{random.randint(2,254)}.{random.randint(2,254)}"
                self._post("/api/checkout",
                           json={"session": sess, "card": f"4222{i:012d}",
                                 "value": 1, "method": "card", "attack": True,
                                 "expect": "fail"},
                           headers={"X-Forwarded-For": ip})
                time.sleep(0.05)
        threading.Thread(target=run, daemon=True).start()
        return f"{attempts} attempts, one per session, rotated fingerprints"

    # ------------------------------------------------------------------
    # R-06 — invoice fraud (real fraudulent order) and its false positive twin
    # ------------------------------------------------------------------
    def invoice_fraud(self):
        self._post("/api/checkout", json={
            "session": "atk-inv", "method": "invoice", "value": 890,
            "first_order": True, "address_mismatch": True, "express": True,
            "attack": True, "fraud": True})
        return "Invoice order on a stolen identity, address redirected"

    def legit_expedition_order(self):
        self._post("/api/checkout", json={
            "session": "cust-lena", "method": "invoice", "value": 1800,
            "first_order": True, "address_mismatch": True, "express": True,
            "attack": False, "fraud": False})
        return "Genuine €1,800 expedition order — the false-positive case"

    # ------------------------------------------------------------------
    # R-01 — skimmer injection (hits the payment-page integrity endpoint)
    # ------------------------------------------------------------------
    def skimmer(self, conditional=False):
        self._post("/api/inject_skimmer", json={"conditional": conditional})
        return ("Conditional skimmer injected (fires 1 in 200)" if conditional
                else "Skimmer injected into a marketing script")

    # ------------------------------------------------------------------
    # R-03 — phished admin login
    # ------------------------------------------------------------------
    def admin_phish(self):
        self._post("/api/admin_login",
                   json={"user": "admin", "password": "Str0ng-Admin-2025", "attack": True})
        return "Phished admin password replayed against the backend"
