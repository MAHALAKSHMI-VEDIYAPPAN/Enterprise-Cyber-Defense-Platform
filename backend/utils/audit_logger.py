from flask import request

from flask_login import current_user

from extensions import db

from models.audit_log import AuditLog


# ==========================================================
# Create Audit Log
# ==========================================================

def log_action(
    action,
    description=None
):
    """
    Safely record a security-related application action.

    Audit logging failures are handled separately so that
    a logging problem does not break the main application.
    """

    try:

        # --------------------------------------------------
        # User Information
        # --------------------------------------------------

        if (
            current_user
            and current_user.is_authenticated
        ):

            user_id = current_user.id

            username = current_user.username

        else:

            user_id = None

            username = "Anonymous"


        # --------------------------------------------------
        # Client IP
        # --------------------------------------------------

        ip_address = request.remote_addr


        # --------------------------------------------------
        # Create Audit Record
        # --------------------------------------------------

        audit_log = AuditLog(

            user_id=user_id,

            username=username,

            action=action,

            description=description,

            ip_address=ip_address

        )


        # --------------------------------------------------
        # Save Audit Record
        # --------------------------------------------------

        db.session.add(
            audit_log
        )

        db.session.commit()


    except Exception as error:

        # --------------------------------------------------
        # Rollback Failed Audit Transaction
        # --------------------------------------------------

        db.session.rollback()


        # --------------------------------------------------
        # Do Not Break Main Application
        # --------------------------------------------------

        print(
            f"[AUDIT LOG ERROR] {error}"
        )