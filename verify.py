import sys
sys.path.insert(0, ".")
from app import app, monitor
from app.data import BREACH_CORPUS

c = app.test_client()

def reset():
    c.post("/api/soc/reset")
    for cid in ["C-01","C-04","C-11","C-12","C-13","C-15","C-16","C-18"]:
        monitor.set_control(cid, True)

def ctl(cid, on): c.post(f"/api/soc/control/{cid}", json={"on": on})

reset()
for email, pw in BREACH_CORPUS * 5:
    c.post("/api/login", json={"email": email, "password": pw, "attack": True})
snap = monitor.snapshot()
blocked = sum(1 for e in snap["events"] if e["outcome"]=="blocked")
print("1. stuffing (C-01 on): blocked at edge =", blocked, "| succeeded =",
      sum(1 for e in snap["events"] if e["kind"]=="login" and e["outcome"]=="success"))

reset(); ctl("C-01", False); ctl("C-18", False)
for email, pw in BREACH_CORPUS * 3:
    c.post("/api/login", json={"email": email, "password": pw, "attack": True})
snap = monitor.snapshot()
print("2. stuffing (off): cracked =",
      sum(1 for e in snap["events"] if e["kind"]=="login" and e["outcome"]=="success"),
      "| FN =", snap["metrics"]["false_negative"])

reset()
c.post("/api/inject_skimmer", json={})
print("3a. skimmer (C-13 on):", monitor.snapshot()["alerts"][0]["title"])
reset(); ctl("C-13", False); ctl("C-11", False); ctl("C-12", False)
c.post("/api/inject_skimmer", json={})
st = c.get("/api/soc/state").get_json()
print("3b. skimmer (all off): exposed =", st["cards_exposed"], "| verdict =", st["alerts"][0]["verdict"])

reset(); ctl("C-13", False); ctl("C-11", False)
c.post("/api/inject_skimmer", json={"conditional": True})
st = c.get("/api/soc/state").get_json()
print("4. conditional skimmer (C-12 on): verdict =", st["alerts"][0]["verdict"], "| exposed =", st["cards_exposed"])

reset()
c.post("/api/checkout", json={"session":"cust","method":"invoice","value":1800,
    "first_order":True,"address_mismatch":True,"express":True,"attack":False,"fraud":False})
snap = monitor.snapshot()
print("5. genuine EUR1800 order: FP =", snap["metrics"]["false_positive"])

reset()
c.post("/api/checkout", json={"session":"atk","method":"invoice","value":890,
    "first_order":True,"address_mismatch":True,"express":True,"attack":True,"fraud":True})
print("6. invoice fraud: TP =", monitor.snapshot()["metrics"]["true_positive"])

reset()
c.post("/api/admin_login", json={"user":"admin","password":"Str0ng-Admin-2025","attack":True})
print("7. admin phish (C-04 on):", monitor.snapshot()["alerts"][0]["title"])

reset()
for i in range(20):
    c.post("/api/checkout", json={"session":f"d-{i}","method":"card","expect":"fail","attack":True})
snap = monitor.snapshot()
print("8. distributed card testing:", [a["control"] for a in snap["alerts"] if a["risk"]=="R-05"][:2] or "missed")

reset()
c.get("/"); c.get("/product/alpspitze"); c.get("/checkout")
c.post("/api/login", json={"email":"lena@example.de","password":"sonnenschein"})
print("9. genuine browsing: alerts =", len(monitor.snapshot()["alerts"]), "(want 0)")

print("\nALL PATHS OK")
