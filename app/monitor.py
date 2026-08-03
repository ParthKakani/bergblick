"""
The security event bus and live detection engine.

Every request the shop serves writes a real event here. The SOC dashboard reads this
same stream and runs detectors over it. Nothing is scripted: a detection fires because
actual requests with actual properties were logged, exactly as a real monitoring system
would work off a real access log.
"""

import time
import threading
from collections import deque, defaultdict
from dataclasses import dataclass, field


# Report thresholds (Section 8.4), expressed in the same terms as the document.
LOGIN_WINDOW_SECONDS = 30
LOGIN_SUCCESS_RATIO_ALERT = 0.35     # success ratio below this over the window = stuffing
LOGIN_MIN_ATTEMPTS = 12              # need volume before the ratio means anything
AUTH_FAILURE_RATIO_ALERT = 0.25      # card authorisation failure ratio
AUTH_MIN_ATTEMPTS = 10
VELOCITY_PER_SESSION = 5             # card auth attempts per session before challenge
FRAUD_REVIEW_THRESHOLD = 400         # € invoice/BNPL order value that triggers review


@dataclass
class Event:
    ts: float
    kind: str                # login / checkout / admin / script / page
    outcome: str             # success / fail / blocked / flagged / ok
    ip: str
    detail: dict = field(default_factory=dict)

    def as_dict(self):
        return {"ts": self.ts, "kind": self.kind, "outcome": self.outcome,
                "ip": self.ip, "detail": self.detail}


@dataclass
class Alert:
    ts: float
    severity: str            # critical / high / medium / info
    rule: str                # detector name
    risk: str                # R-xx it maps to
    control: str             # C-xx that addresses it
    title: str
    detail: str
    verdict: str = "true_positive"   # for the metrics panel

    def as_dict(self):
        return {"ts": self.ts, "severity": self.severity, "rule": self.rule,
                "risk": self.risk, "control": self.control, "title": self.title,
                "detail": self.detail, "verdict": self.verdict}


class SecurityMonitor:
    """Holds the live event stream, the alert list, and the running detectors."""

    def __init__(self):
        self._lock = threading.Lock()
        self.events = deque(maxlen=500)
        self.alerts = deque(maxlen=120)
        self.metrics = defaultdict(int)          # true_positive / false_positive / false_negative
        self.controls = {}                       # set by the app: cid -> bool
        # rolling state for ratio detectors
        self._login_events = deque(maxlen=400)
        self._auth_events = deque(maxlen=400)
        self._session_auth = defaultdict(list)   # session -> [ts]
        self.stats = defaultdict(int)            # headline counters for the dashboard

    # ---- control state ----
    def control_on(self, cid: str) -> bool:
        return bool(self.controls.get(cid, True))

    def set_control(self, cid: str, on: bool):
        self.controls[cid] = on

    # ---- event ingestion (called by real request handlers) ----
    def log(self, kind, outcome, ip, **detail):
        ev = Event(ts=time.time(), kind=kind, outcome=outcome, ip=ip, detail=detail)
        with self._lock:
            self.events.appendleft(ev)
            self.stats["events_total"] += 1
            self._route(ev)
        return ev

    def _route(self, ev: Event):
        if ev.kind == "login":
            self._login_events.append(ev)
            if ev.outcome == "success":
                self.stats["logins_ok"] += 1
            elif ev.outcome == "fail":
                self.stats["logins_fail"] += 1
            self._detect_stuffing(ev)
        elif ev.kind == "checkout":
            self._auth_events.append(ev)
            sess = ev.detail.get("session", "?")
            self._session_auth[sess].append(ev.ts)
            if ev.outcome == "fail":
                self.stats["auth_fail"] += 1
            self._detect_card_testing(ev)
            self._detect_fraud_order(ev)
        elif ev.kind == "script":
            self._detect_skimmer(ev)
        elif ev.kind == "admin":
            self._detect_admin(ev)

    # ---- detectors: each maps to a risk and a control from the report ----

    def _recent(self, seq, window):
        now = time.time()
        return [e for e in seq if now - e.ts <= window]

    def _detect_stuffing(self, ev):
        """C-18 login success ratio → R-02 credential stuffing."""
        if not self.control_on("C-18"):
            if ev.detail.get("attack"):
                self._maybe_missed("R-02", "credential stuffing")
            return
        recent = self._recent(self._login_events, LOGIN_WINDOW_SECONDS)
        if len(recent) < LOGIN_MIN_ATTEMPTS:
            return
        ok = sum(1 for e in recent if e.outcome == "success")
        ratio = ok / len(recent)
        if ratio < LOGIN_SUCCESS_RATIO_ALERT:
            self._raise("high", "Login success ratio", "R-02", "C-01/C-18",
                        "Credential-stuffing signature",
                        f"{len(recent)} login attempts in {LOGIN_WINDOW_SECONDS}s with a "
                        f"{ratio:.0%} success ratio — well below the {LOGIN_SUCCESS_RATIO_ALERT:.0%} "
                        "alert level. Watching the ratio, not the volume, is what makes this "
                        "visible against normal traffic.",
                        dedup_key="stuffing")

    def _detect_card_testing(self, ev):
        """C-15 velocity + C-18 aggregate ratio → R-05 card testing."""
        sess = ev.detail.get("session", "?")
        now = time.time()
        self._session_auth[sess] = [t for t in self._session_auth[sess] if now - t <= 60]
        per_session = len(self._session_auth[sess])

        if self.control_on("C-15") and per_session > VELOCITY_PER_SESSION:
            self._raise("medium", "Authorisation velocity", "R-05", "C-15",
                        "Card testing blocked by velocity limit",
                        f"{per_session} authorisation attempts from one session in 60s, above "
                        f"the limit of {VELOCITY_PER_SESSION}. Escalated to challenge.",
                        dedup_key=f"velocity:{sess}")
            return

        recent = self._recent(self._auth_events, 60)
        if len(recent) >= AUTH_MIN_ATTEMPTS:
            fails = sum(1 for e in recent if e.outcome == "fail")
            ratio = fails / len(recent)
            if ratio > AUTH_FAILURE_RATIO_ALERT:
                if self.control_on("C-18"):
                    self._raise("medium", "Authorisation failure ratio", "R-05", "C-18",
                                "Distributed card testing (aggregate)",
                                f"Authorisation failure ratio at {ratio:.0%} across {len(recent)} "
                                "attempts. No single session crossed the velocity limit — this is "
                                "only visible in aggregate, which is the report's answer to the "
                                "distributed low-rate false negative.",
                                dedup_key="cardtest-agg")
                elif ev.detail.get("attack"):
                    self._maybe_missed("R-05", "distributed card testing")

    def _detect_fraud_order(self, ev):
        """C-16 fraud scoring → R-06 invoice fraud, incl. the false positive."""
        if ev.detail.get("method") != "invoice":
            return
        if not self.control_on("C-16"):
            if ev.detail.get("fraud"):
                self._maybe_missed("R-06", "invoice fraud")
            return
        value = ev.detail.get("value", 0)
        score = 0
        reasons = []
        if value > FRAUD_REVIEW_THRESHOLD:
            score += 2; reasons.append(f"€{value:,}")
        if ev.detail.get("first_order"):
            score += 2; reasons.append("first order")
        if ev.detail.get("address_mismatch"):
            score += 2; reasons.append("delivery≠billing")
        if ev.detail.get("express"):
            score += 1; reasons.append("express")
        if score >= 5:
            is_fraud = ev.detail.get("fraud", False)
            verdict = "true_positive" if is_fraud else "false_positive"
            sev = "high" if is_fraud else "info"
            note = ("Held for review — genuinely fraudulent." if is_fraud else
                    "Held for review — but this is a genuine high-value customer. "
                    "Held, never auto-rejected. One of ~40–70 such false positives a month.")
            self._raise(sev, "Fraud scoring", "R-06", "C-16",
                        "Invoice order held for review",
                        f"Score {score} ({', '.join(reasons)}). {note}",
                        verdict=verdict, dedup_key=f"fraud:{ev.ts}")

    def _detect_skimmer(self, ev):
        """C-11/C-12/C-13 → R-01 e-skimming."""
        if ev.outcome == "blocked":
            self._raise("info", "Payment-page integrity", "R-01", ev.detail.get("by", "C-11"),
                        "Skimmer blocked on the payment page",
                        ev.detail.get("msg", "An unauthorised script was prevented from "
                        "running or exfiltrating."),
                        dedup_key="skim-block")
        elif ev.outcome == "flagged":
            self._raise("high", "Tamper detection", "R-01", "C-12",
                        "Payment page changed unexpectedly",
                        ev.detail.get("msg", "The delivered script set differs from the "
                        "approved baseline."),
                        dedup_key="skim-flag")
        elif ev.outcome == "fail":
            self._raise("critical", "E-skimming active", "R-01", "—",
                        "Card data leaving the payment page",
                        ev.detail.get("msg", "A skimmer is exfiltrating card data and no "
                        "control stopped it. This is the top risk realised."),
                        verdict="false_negative", dedup_key="skim-live")

    def _detect_admin(self, ev):
        """C-04 staff MFA + C-19 logging → R-03 admin compromise."""
        if ev.outcome == "blocked":
            self._raise("info", "Staff authentication", "R-03", "C-04",
                        "Admin login blocked — MFA required",
                        "A valid password was supplied without the second factor. Denied and "
                        "logged. This control costs nothing in conversion.",
                        dedup_key="admin-mfa")
        elif ev.outcome == "success" and ev.detail.get("attack"):
            self._raise("critical", "Staff authentication", "R-03", "—",
                        "Administrator account compromised",
                        "Backend access obtained with a phished password and no second factor.",
                        verdict="false_negative", dedup_key="admin-breach")

    # ---- alert plumbing ----
    _dedup = {}

    def _raise(self, severity, rule, risk, control, title, detail,
               verdict="true_positive", dedup_key=None):
        now = time.time()
        if dedup_key:
            last = self._dedup.get(dedup_key, 0)
            if now - last < 4:            # collapse repeats within 4s
                return
            self._dedup[dedup_key] = now
        alert = Alert(now, severity, rule, risk, control, title, detail, verdict)
        self.alerts.appendleft(alert)
        self.metrics[verdict] += 1
        self.stats["alerts_total"] += 1

    def _maybe_missed(self, risk, what):
        """Record a false negative when an attack ran with the relevant control off."""
        self.metrics["false_negative"] += 1
        self.stats["missed_total"] += 1
        self.alerts.appendleft(Alert(time.time(), "critical", "—", risk, "—",
                                     f"Undetected: {what}",
                                     f"An attack matching {risk} ran while its detecting control "
                                     "was disabled. Nothing fired — the documented gap, reproduced.",
                                     "false_negative"))

    # ---- dashboard reads ----
    def snapshot(self):
        with self._lock:
            m = dict(self.metrics)
            tp, fp, fn = m.get("true_positive", 0), m.get("false_positive", 0), m.get("false_negative", 0)
            recall = round(tp / (tp + fn) * 100, 1) if (tp + fn) else None
            precision = round(tp / (tp + fp) * 100, 1) if (tp + fp) else None
            return {
                "events": [e.as_dict() for e in list(self.events)[:40]],
                "alerts": [a.as_dict() for a in list(self.alerts)[:40]],
                "metrics": {"true_positive": tp, "false_positive": fp,
                            "false_negative": fn, "recall": recall, "precision": precision},
                "stats": dict(self.stats),
                "controls": dict(self.controls),
            }


monitor = SecurityMonitor()
