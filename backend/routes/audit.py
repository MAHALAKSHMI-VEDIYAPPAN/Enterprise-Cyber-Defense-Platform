from flask import (
    Blueprint,
    render_template,
    request
)

from models.audit_log import AuditLog

from utils.role_required import role_required


# ==========================================================
# Audit Logs Blueprint
# ==========================================================

audit_bp = Blueprint(
    "audit",
    __name__
)


# ==========================================================
# Audit Logs
# ==========================================================

@audit_bp.route(
    "/audit-logs",
    methods=["GET"]
)
@role_required("Admin")
def audit_logs():

    # ======================================================
    # Search
    # ======================================================

    search = request.args.get(
        "search",
        ""
    ).strip()


    # ======================================================
    # Action Filter
    # ======================================================

    action = request.args.get(
        "action",
        ""
    ).strip()


    # ======================================================
    # Username Filter
    # ======================================================

    username = request.args.get(
        "username",
        ""
    ).strip()


    # ======================================================
    # Base Query
    # ======================================================

    query = AuditLog.query


    # ======================================================
    # Search
    # ======================================================

    if search:

        search_pattern = f"%{search}%"

        query = query.filter(

            AuditLog.description.ilike(
                search_pattern
            )
            |
            AuditLog.action.ilike(
                search_pattern
            )
            |
            AuditLog.username.ilike(
                search_pattern
            )
            |
            AuditLog.ip_address.ilike(
                search_pattern
            )

        )


    # ======================================================
    # Action Filter
    # ======================================================

    if action:

        query = query.filter(
            AuditLog.action == action
        )


    # ======================================================
    # Username Filter
    # ======================================================

    if username:

        query = query.filter(
            AuditLog.username == username
        )


    # ======================================================
    # Get Audit Logs
    # ======================================================

    logs = query.order_by(

        AuditLog.timestamp.desc()

    ).all()


    # ======================================================
    # Get Available Actions
    # ======================================================

    actions = [

        row[0]

        for row in AuditLog.query.with_entities(
            AuditLog.action
        ).distinct().order_by(
            AuditLog.action.asc()
        ).all()

    ]


    # ======================================================
    # Get Available Users
    # ======================================================

    users = [

        row[0]

        for row in AuditLog.query.with_entities(
            AuditLog.username
        ).filter(
            AuditLog.username.isnot(None)
        ).distinct().order_by(
            AuditLog.username.asc()
        ).all()

    ]


    # ======================================================
    # Render Audit Logs
    # ======================================================

    return render_template(

        "audit.html",

        logs=logs,

        actions=actions,

        users=users,

        search=search,

        selected_action=action,

        selected_username=username

    )