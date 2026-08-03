"""Shop data and control registry for the live demo."""

from werkzeug.security import generate_password_hash

PRODUCTS = [
    {"id": "alpspitze",  "name": "Alpspitze 45L Expeditionsrucksack", "price": 1699,
     "cat": "Mountaineering", "blurb": "Alpine expedition pack, 45 litres, Pine."},
    {"id": "gipfel",     "name": "Gipfel Kompass-Set", "price": 148,
     "cat": "Navigation", "blurb": "Precision compass and map tool set."},
    {"id": "biwak",      "name": "Biwak 2 Leichtzelt", "price": 429,
     "cat": "Tents", "blurb": "Two-person ultralight tent, 1.9 kg."},
    {"id": "steigeisen", "name": "Nordwand Steigeisen", "price": 189,
     "cat": "Mountaineering", "blurb": "12-point automatic crampons."},
    {"id": "hardshell",  "name": "Sturm Hardshell Jacke", "price": 349,
     "cat": "Clothing", "blurb": "3-layer waterproof shell, Pro membrane."},
    {"id": "stirnlampe", "name": "Gipfel 600 Stirnlampe", "price": 79,
     "cat": "Equipment", "blurb": "600-lumen rechargeable headtorch."},
]

# A handful of real accounts. Passwords are properly hashed (bcrypt-style via werkzeug).
# 'lena' uses a password that also appears in the demo "breach corpus" — so credential
# stuffing can genuinely succeed against exactly one account, as in the real world.
CUSTOMERS = {
    "lena@example.de":  {"name": "Lena Vogt",   "pw": "sonnenschein",   "breached": True},
    "mارco@example.de": {"name": "Marco Reÿes",  "pw": "K7$mtn!pass",    "breached": False},
    "sofia@example.de": {"name": "Sofia Braun",  "pw": "Gipfel2025xz",   "breached": False},
}
# fix the accidental non-ascii key above deterministically
CUSTOMERS = {
    "lena@example.de":  {"name": "Lena Vogt",  "pw": "sonnenschein", "breached": True},
    "marco@example.de": {"name": "Marco Reyes", "pw": "K7$mtn!pass",  "breached": False},
    "sofia@example.de": {"name": "Sofia Braun", "pw": "Gipfel2025xz", "breached": False},
}

for c in CUSTOMERS.values():
    c["pw_hash"] = generate_password_hash(c["pw"])

# A public breach corpus the attacker uses. Only 'sonnenschein' overlaps a real account.
BREACH_CORPUS = [
    ("lena@example.de", "sonnenschein"),
    ("lena@example.de", "password1"),
    ("marco@example.de", "hunter2"),
    ("marco@example.de", "letmein"),
    ("sofia@example.de", "qwertz123"),
    ("unknown@example.de", "12345678"),
    ("test@example.de", "iloveyou"),
    ("admin@example.de", "admin"),
]

ADMIN = {"user": "admin", "pw": "Str0ng-Admin-2025", "pw_hash": None}
ADMIN["pw_hash"] = generate_password_hash(ADMIN["pw"])

# The 14 scripts on the payment page (assumption A4). owner = IT or Marketing.
PAYMENT_SCRIPTS = [
    {"name": "Checkout bundle",      "origin": "shop.bergblick.de",       "owner": "IT"},
    {"name": "Payment provider SDK", "origin": "sdk.paynord.com",         "owner": "IT"},
    {"name": "Session analytics",    "origin": "cdn.metrics-eu.com",      "owner": "Marketing"},
    {"name": "Tag manager",          "origin": "tags.bergblick.de",       "owner": "Marketing"},
    {"name": "A/B testing",          "origin": "experiments.optimizr.io", "owner": "Marketing"},
    {"name": "Advertising pixel",    "origin": "px.adnetwork-eu.com",     "owner": "Marketing"},
]

# Controls the SOC can toggle. Maps to the report; default all on.
CONTROLS = [
    {"id": "C-01", "name": "Bot management", "risks": ["R-02", "R-05"]},
    {"id": "C-04", "name": "Staff MFA", "risks": ["R-03"]},
    {"id": "C-11", "name": "CSP + SRI on payment page", "risks": ["R-01"]},
    {"id": "C-12", "name": "Payment-page tamper detection", "risks": ["R-01"]},
    {"id": "C-13", "name": "Tag-manager governance", "risks": ["R-01"]},
    {"id": "C-15", "name": "Authorisation velocity limits", "risks": ["R-05"]},
    {"id": "C-16", "name": "Fraud scoring + review", "risks": ["R-06"]},
    {"id": "C-18", "name": "Ratio-based monitoring", "risks": ["R-02", "R-05"]},
]
