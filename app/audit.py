from datetime import datetime

AUDIT_LOG = []


def log_action(user, role, action, details=""):
    AUDIT_LOG.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user": user,
        "role": role,
        "action": action,
        "details": details
    })


def get_logs():
    return list(reversed(AUDIT_LOG))