from werkzeug.security import generate_password_hash, check_password_hash

USERS = {

    "lena@example.de": {
        "name": "Lena",
        "password": generate_password_hash("customer123"),
        "role": "customer",
        "active": True
    },

    "admin@bergblick.de": {
        "name": "Store Admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "active": True
    },

    "soc@bergblick.de": {
        "name": "SOC Analyst",
        "password": generate_password_hash("soc123"),
        "role": "soc",
        "active": True
    }
}
def authenticate(email, password):

    user = USERS.get(email)

    if not user:
        return None

    if not user["active"]:
        return None

    if check_password_hash(user["password"], password):
        return user

    return None
def get_user(email):
    return USERS.get(email)
def get_role(email):

    user = USERS.get(email)

    if user:
        return user["role"]

    return None