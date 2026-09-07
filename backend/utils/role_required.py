from functools import wraps

from flask import (
    abort,
    flash,
    redirect,
    url_for
)

from flask_login import (
    current_user,
    login_required
)

from utils.audit_logger import log_action


# ==========================================================
# Role-Based Access Control
# ==========================================================

def role_required(*allowed_roles):

    def decorator(view_function):

        @wraps(view_function)
        @login_required
        def wrapped_view(*args, **kwargs):

            # --------------------------------------------------
            # Check User Role
            # --------------------------------------------------

            if not current_user.is_authenticated:

                return redirect(
                    url_for("auth.login")
                )


            # --------------------------------------------------
            # Authorization Check
            # --------------------------------------------------

            if current_user.role not in allowed_roles:

                # ----------------------------------------------
                # Audit Unauthorized Access
                # ----------------------------------------------

                log_action(
                    "ACCESS_DENIED",
                    (
                        f"User '{current_user.username}' "
                        f"with role '{current_user.role}' "
                        f"attempted to access a restricted resource."
                    )
                )


                # ----------------------------------------------
                # User-Friendly Message
                # ----------------------------------------------

                flash(
                    "You do not have permission to access this resource.",
                    "danger"
                )


                # ----------------------------------------------
                # Forbidden
                # ----------------------------------------------

                abort(403)


            # --------------------------------------------------
            # Authorized
            # --------------------------------------------------

            return view_function(
                *args,
                **kwargs
            )

        return wrapped_view

    return decorator