#!/usr/bin/env python3
"""
Bergblick — live shop with a side-by-side SOC dashboard.

Run:   python run.py
Then open two browser windows:
    http://127.0.0.1:5001/         the shop
    http://127.0.0.1:5001/soc      the security operations dashboard

Trigger attacks from the control panel on the SOC page. They fire **real HTTP requests**
at the shop's own routes; the SOC detects them from the resulting event log. Toggle a
control off, run the same attack, and watch the difference — including the documented
false positives and false negatives.
"""

import os
import secrets

from flask import Flask, jsonify, render_template, request, session, redirect, url_for
from werkzeug.security import check_password_hash

from .monitor import monitor
from .attacker import Attacker
from .data import (ADMIN, CONTROLS, CUSTOMERS, PAYMENT_SCRIPTS, PRODUCTS)
from .users import authenticate
from .security import role_required
from .audit import log_action
from .audit import get_logs

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# skimmer state on the payment page
PAGE = {"skimmer": False, "conditional": False, "cards_exposed": 0}

# initialise control state (all on)
for c in CONTROLS:
    monitor.set_control(c["id"], True)

_attacker = None
def attacker():
    global _attacker
    if _attacker is None:
        _attacker = Attacker(f"http://127.0.0.1:{os.environ.get('PORT','5001')}")
    return _attacker


def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")


# ============================ SHOP (customer-facing) ============================

@app.route("/")
def home():
    return render_template("shop.html", products=PRODUCTS,
                           user=session.get("user"))

@app.route("/product/<pid>")
def product(pid):
    p = next((x for x in PRODUCTS if x["id"] == pid), None)
    if not p:
        return redirect(url_for("home"))
    monitor.log("page", "ok", client_ip(), path=f"/product/{pid}")
    return render_template("product.html", p=p, user=session.get("user"))

@app.route("/checkout")
def checkout_page():
    monitor.log("page", "ok", client_ip(), path="/checkout")
    return render_template("checkout.html", scripts=PAYMENT_SCRIPTS,
                           skimmer=PAGE["skimmer"], user=session.get("user"))


# ---- real login endpoint (used by the form AND by the attacker) ----
@app.route("/api/login", methods=["POST"])
def api_login():
    body = request.get_json(silent=True) or request.form
    email = (body.get("email") or "").strip().lower()
    pw = body.get("password") or ""
    attack = bool(body.get("attack"))
    ip = client_ip()

    user = authenticate(email, pw)

    # C-01 bot management: challenge attack-flagged traffic at the edge
    if attack and monitor.control_on("C-01"):
        monitor.log("login", "blocked", ip, email=email, attack=True)
        return jsonify({"ok": False, "blocked": "bot-management"}), 429

    if user:
        monitor.log("login", "success", ip, email=email, attack=attack)
        if not attack:
            session["user"] = user["name"]
            session["role"] = user["role"]
            session["email"] = email

            log_action(
                session["user"],
                session["role"],
                "User Login",
                f"{email} logged in successfully"
            )
        return jsonify({
            "ok": True,
            "user": user["name"],
            "role": user["role"]
        })
    monitor.log("login", "fail", ip, email=email, attack=attack)
    return jsonify({"ok": False}), 401

@app.route("/logout")
def logout():
    log_action(
        session.get("user"),
        session.get("role"),
        "User Logout"
    )
    session.clear()
    return redirect(url_for("home"))


# ---- real checkout endpoint ----
@app.route("/api/checkout", methods=["POST"])
def api_checkout():
    body = request.get_json(silent=True) or request.form
    ip = client_ip()
    method = body.get("method", "card")
    sess = body.get("session", "web-" + (session.get("user") or "guest"))

    if method == "invoice":
        monitor.log("checkout", "flagged" if body.get("fraud") else "ok", ip,
                    session=sess, method="invoice",
                    value=int(body.get("value", 0)),
                    first_order=bool(body.get("first_order")),
                    address_mismatch=bool(body.get("address_mismatch")),
                    express=bool(body.get("express")),
                    fraud=bool(body.get("fraud")), attack=bool(body.get("attack")))
        return jsonify({"ok": True})

    # card path: attacker attempts fail authorisation (invalid test numbers)
    outcome = "fail" if body.get("expect") == "fail" else "success"
    monitor.log("checkout", outcome, ip, session=sess, method="card",
                attack=bool(body.get("attack")))
    return jsonify({"ok": outcome == "success"})


# ---- payment-page integrity (skimmer lifecycle) ----
@app.route("/api/inject_skimmer", methods=["POST"])
def api_inject_skimmer():
    body = request.get_json(silent=True) or {}
    conditional = bool(body.get("conditional"))
    ip = client_ip()

    # C-13 governance: publishing to the payment page is blocked outright
    if monitor.control_on("C-13"):
        monitor.log("script", "blocked", ip, by="C-13",
                    msg="A marketing account tried to add a script to the payment page. "
                        "Publish rights belong to IT — the change was rejected before going live.")
        return jsonify({"result": "blocked-by-governance"})

    PAGE["skimmer"] = True
    PAGE["conditional"] = conditional

    # C-11 CSP/SRI: the skimmer runs but cannot exfiltrate / fails integrity
    if monitor.control_on("C-11"):
        monitor.log("script", "blocked", ip, by="C-11",
                    msg="Skimmer added, but Subresource Integrity failed and the CSP "
                        "connect-src allow-list refuses its exfiltration endpoint. "
                        "Card data cannot leave the browser.")
        PAGE["skimmer"] = False
        return jsonify({"result": "blocked-by-csp"})

    # C-12 tamper detection: caught unless it is a conditional/rare payload
    if monitor.control_on("C-12") and not conditional:
        monitor.log("script", "flagged", ip,
                    msg="Tamper detection compared the delivered page against the approved "
                        "baseline and found an unregistered script. Alert raised.")
        return jsonify({"result": "flagged-by-tamper"})

    # nothing stopped it
    exposed = 27552 if not conditional else 340
    PAGE["cards_exposed"] += exposed
    monitor.log("script", "fail", ip,
                msg=(f"Skimmer live and exfiltrating. ~{exposed:,} card entries exposed "
                     + ("(conditional payload — evaded tamper detection, discovered weeks "
                        "later by the acquiring bank)." if conditional
                        else "before discovery.")))
    return jsonify({"result": "exfiltrating", "exposed": exposed})

@app.route("/api/clear_skimmer", methods=["POST"])
def api_clear_skimmer():
    PAGE["skimmer"] = False
    PAGE["conditional"] = False
    return jsonify({"ok": True})


# ---- admin login ----
@app.route("/api/admin_login", methods=["POST"])
def api_admin_login():
    body = request.get_json(silent=True) or request.form
    ip = client_ip()
    pw_ok = check_password_hash(ADMIN["pw_hash"], body.get("password", ""))
    attack = bool(body.get("attack"))

    if pw_ok and monitor.control_on("C-04"):
        monitor.log("admin", "blocked", ip, attack=attack)
        return jsonify({"ok": False, "blocked": "mfa-required"})
    if pw_ok:
        monitor.log("admin", "success", ip, attack=attack)
        return jsonify({"ok": True})
    monitor.log("admin", "fail", ip, attack=attack)
    return jsonify({"ok": False}), 401


# ============================ SOC (analyst-facing) ============================

@app.route("/soc")
@role_required("soc")
def soc():
    return render_template("soc.html", controls=CONTROLS)

# ===========================
# Additional Security Pages
# ===========================

@app.route("/risk-register")
@role_required("soc")
def risk_register():
    return render_template("risk_register.html")


@app.route("/stride")
@role_required("soc")
def stride():
    return render_template("stride.html")


@app.route("/architecture")
@role_required("soc")
def architecture():
    return render_template("architecture.html")


@app.route("/incident-response")
@role_required("soc")
def incident_response():
    return render_template("incident_response.html")


@app.route("/testing")
@role_required("soc")
def testing():
    return render_template("testing.html")


@app.route("/reports")
@role_required("soc")
def reports():
    return render_template("reports.html")

print(">>> Risk Register routes loaded <<<")

@app.route("/hello-test")
def hello_test():
    return "Hello! This is the correct Flask app."

@app.route("/api/soc/state")
def soc_state():
    snap = monitor.snapshot()
    snap["cards_exposed"] = PAGE["cards_exposed"]
    snap["skimmer_live"] = PAGE["skimmer"]
    return jsonify(snap)

@app.route("/api/soc/control/<cid>", methods=["POST"])
def soc_control(cid):
    body = request.get_json(silent=True) or {}
    monitor.set_control(cid, bool(body.get("on", True)))
    return jsonify({"id": cid, "on": monitor.control_on(cid)})

@app.route("/api/soc/attack/<name>", methods=["POST"])
def soc_attack(name):
    a = attacker()
    fn = {
        "stuffing": a.credential_stuffing,
        "card_crude": a.card_testing_crude,
        "card_dist": a.card_testing_distributed,
        "invoice_fraud": a.invoice_fraud,
        "legit_order": a.legit_expedition_order,
        "skimmer": lambda: a.skimmer(conditional=False),
        "skimmer_cond": lambda: a.skimmer(conditional=True),
        "admin_phish": a.admin_phish,
    }.get(name)
    if not fn:
        return jsonify({"error": "unknown"}), 404
    msg = fn()
    return jsonify({"launched": name, "msg": msg})

@app.route("/api/soc/reset", methods=["POST"])
def soc_reset():
    monitor.events.clear(); monitor.alerts.clear()
    monitor.metrics.clear(); monitor.stats.clear()
    monitor._login_events.clear(); monitor._auth_events.clear()
    monitor._session_auth.clear(); monitor._dedup.clear()
    PAGE["skimmer"] = False; PAGE["conditional"] = False; PAGE["cards_exposed"] = 0
    return jsonify({"ok": True})

@app.route("/admin")
@role_required("admin")
def admin():

    return render_template(
        "admin.html",
        user=session.get("user")
    )
@app.route("/audit")
@role_required("soc")
def audit():

    return render_template(
        "audit.html",
        logs=get_logs()
    )
@app.route("/timeline")
@role_required("soc")
def timeline():

    return render_template(
        "timeline.html",
        logs=get_logs()
    )
@app.route("/ai")
def ai():
    return render_template("ai_recommendations.html")