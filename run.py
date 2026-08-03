#!/usr/bin/env python3
import os

os.environ.setdefault("PORT", "5001")

import app

print("Loaded app from:", app.__file__)

from app import app as flask_app

print("\nRegistered routes:")
for rule in sorted(flask_app.url_map.iter_rules(), key=lambda r: str(r)):
    print(rule)

if __name__ == "__main__":
    print("\n  Bergblick — live shop + SOC")
    print("  Shop: http://127.0.0.1:5001/")
    print("  SOC:  http://127.0.0.1:5001/soc\n")
    flask_app.run(
        host="127.0.0.1",
        port=int(os.environ["PORT"]),
        debug=False,
        threaded=True,
    )