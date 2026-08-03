from functools import wraps
from flask import session, abort


def role_required(*roles):
    """
    Allow access only to users whose role is in the allowed roles.
    Example:
        @role_required("soc")
        @role_required("admin", "soc")
    """

    def decorator(view):

        @wraps(view)
        def wrapped(*args, **kwargs):

            role = session.get("role")

            if role not in roles:
                abort(403)

            return view(*args, **kwargs)

        return wrapped

    return decorator