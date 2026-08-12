from functools import wraps

from flask import request

from flask_login import current_user

from utils.audit_logger import log_action


# ==========================================================
# Audit Logging Helper
# ==========================================================

def audit_action(action, description=None):
    """
    Log an application action.

    Example:
        audit_action(
            "ASSET_CREATED",
            "Created asset Server-01"
        )
    """

    try:
        if callable(description):
            description = description()

        log_action(
            action=action,
            description=description
        )

    except Exception as error:
        # Audit failure must never break the application
        print(
            f"[AUDIT ERROR] {error}"
        )


# ==========================================================
# Audit Decorator
# ==========================================================

def audit_route(action, description=None):
    """
    Automatically create an audit log after a successful route.

    Example:

        @audit_route(
            "ASSET_DELETED",
            "Asset deleted"
        )
    """

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            response = function(
                *args,
                **kwargs
            )

            try:

                final_description = description

                if callable(description):

                    final_description = description(
                        *args,
                        **kwargs
                    )

                log_action(
                    action=action,
                    description=final_description
                )

            except Exception as error:

                print(
                    f"[AUDIT ERROR] {error}"
                )

            return response

        return wrapper

    return decorator