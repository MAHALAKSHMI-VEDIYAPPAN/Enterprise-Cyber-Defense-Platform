from datetime import datetime

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request
)

from flask_login import (
    login_required,
    current_user
)

from extensions import db

from models.remediation import Remediation
from models.asset import Asset
from models.scan import Scan

from utils.audit_logger import log_action


# ==========================================================
# Remediation Blueprint
# ==========================================================

remediation_bp = Blueprint(
    "remediation",
    __name__
)


# ==========================================================
# Generate Remediation ID
# ==========================================================

def generate_remediation_id():

    last_item = Remediation.query.order_by(
        Remediation.id.desc()
    ).first()

    if not last_item:

        next_number = 1

    else:

        next_number = last_item.id + 1

    return (
        f"REM-{next_number:04d}"
    )


# ==========================================================
# Remediation Dashboard
# ==========================================================

@remediation_bp.route(
    "/remediation",
    methods=["GET"]
)
@login_required
def remediation():

    # ======================================================
    # Filters
    # ======================================================

    search = request.args.get(
        "search",
        ""
    ).strip()

    status_filter = request.args.get(
        "status",
        ""
    ).strip()

    severity_filter = request.args.get(
        "severity",
        ""
    ).strip()


    # ======================================================
    # Base Query
    # ======================================================

    query = Remediation.query


    # ======================================================
    # Search
    # ======================================================

    if search:

        pattern = f"%{search}%"

        query = query.filter(
            db.or_(
                Remediation.remediation_id.ilike(pattern),
                Remediation.title.ilike(pattern),
                Remediation.cve_id.ilike(pattern),
                Remediation.assigned_to.ilike(pattern)
            )
        )


    # ======================================================
    # Status Filter
    # ======================================================

    if status_filter:

        query = query.filter(
            Remediation.status == status_filter
        )


    # ======================================================
    # Severity Filter
    # ======================================================

    if severity_filter:

        query = query.filter(
            Remediation.severity == severity_filter
        )


    # ======================================================
    # Get Records
    # ======================================================

    remediations = query.order_by(
        Remediation.created_at.desc()
    ).all()


    # ======================================================
    # Statistics
    # ======================================================

    total_remediations = Remediation.query.count()


    open_remediations = Remediation.query.filter_by(
        status="Open"
    ).count()


    in_progress_remediations = Remediation.query.filter_by(
        status="In Progress"
    ).count()


    verified_count = Remediation.query.filter_by(
        status="Verified"
    ).count()


    # ======================================================
    # Severity Counts
    # ======================================================

    critical_count = Remediation.query.filter_by(
        severity="Critical"
    ).count()


    high_count = Remediation.query.filter_by(
        severity="High"
    ).count()


    medium_count = Remediation.query.filter_by(
        severity="Medium"
    ).count()


    low_count = Remediation.query.filter_by(
        severity="Low"
    ).count()


    # ======================================================
    # Render
    # ======================================================

    return render_template(

        "remediation.html",

        remediations=remediations,

        total_remediations=total_remediations,

        open_remediations=open_remediations,

        in_progress_remediations=in_progress_remediations,

        verified_count=verified_count,

        critical_count=critical_count,

        high_count=high_count,

        medium_count=medium_count,

        low_count=low_count,

        search=search,

        status_filter=status_filter,

        severity_filter=severity_filter

    )


# ==========================================================
# Create Remediation
# ==========================================================

@remediation_bp.route(
    "/remediation/create",
    methods=["GET", "POST"]
)
@login_required
def create_remediation():

    # ======================================================
    # Permission
    # ======================================================

    if current_user.role not in [
        "Admin",
        "Analyst"
    ]:

        flash(
            "You do not have permission to create remediation tasks.",
            "danger"
        )

        return redirect(
            url_for(
                "remediation.remediation"
            )
        )


    # ======================================================
    # Load Assets and Scans
    # ======================================================

    assets = Asset.query.order_by(
        Asset.asset_name.asc()
    ).all()


    scans = Scan.query.order_by(
        Scan.scan_date.desc()
    ).all()


    # ======================================================
    # POST
    # ======================================================

    if request.method == "POST":

        title = (
            request.form.get(
                "title",
                ""
            ).strip()
        )

        cve_id = (
            request.form.get(
                "cve_id",
                ""
            ).strip()
        )

        severity = (
            request.form.get(
                "severity",
                "Medium"
            ).strip()
        )

        description = (
            request.form.get(
                "description",
                ""
            ).strip()
        )

        recommendation = (
            request.form.get(
                "recommendation",
                ""
            ).strip()
        )

        assigned_to = (
            request.form.get(
                "assigned_to",
                ""
            ).strip()
        )

        notes = (
            request.form.get(
                "notes",
                ""
            ).strip()
        )


        # ==================================================
        # Asset
        # ==================================================

        asset_id_raw = (
            request.form.get(
                "asset_id",
                ""
            ).strip()
        )

        asset_id = None

        if asset_id_raw:

            try:

                asset_id = int(
                    asset_id_raw
                )

            except ValueError:

                asset_id = None


        # ==================================================
        # Scan
        # ==================================================

        scan_id_raw = (
            request.form.get(
                "scan_id",
                ""
            ).strip()
        )

        scan_id = None

        if scan_id_raw:

            try:

                scan_id = int(
                    scan_id_raw
                )

            except ValueError:

                scan_id = None


        # ==================================================
        # Validation
        # ==================================================

        if not title:

            flash(
                "Remediation title is required.",
                "danger"
            )

            return render_template(
                "create_remediation.html",
                assets=assets,
                scans=scans
            )


        if severity not in [
            "Critical",
            "High",
            "Medium",
            "Low"
        ]:

            severity = "Medium"


        # ==================================================
        # Create Record
        # ==================================================

        item = Remediation(

            remediation_id=generate_remediation_id(),

            title=title,

            cve_id=(
                cve_id
                if cve_id
                else None
            ),

            asset_id=asset_id,

            scan_id=scan_id,

            severity=severity,

            description=(
                description
                if description
                else None
            ),

            recommendation=(
                recommendation
                if recommendation
                else None
            ),

            status="Open",

            assigned_to=(
                assigned_to
                if assigned_to
                else None
            ),

            notes=(
                notes
                if notes
                else None
            )

        )


        db.session.add(
            item
        )


        try:

            db.session.commit()

        except Exception as error:

            db.session.rollback()

            flash(
                "Unable to create remediation record.",
                "danger"
            )

            print(
                f"[REMEDIATION ERROR] {error}"
            )

            return render_template(
                "create_remediation.html",
                assets=assets,
                scans=scans
            )


        # ==================================================
        # Audit
        # ==================================================

        log_action(
            "REMEDIATION_CREATED",
            (
                f"Remediation created: "
                f"{item.remediation_id}. "
                f"Title: {item.title}. "
                f"Severity: {item.severity}."
            )
        )


        flash(
            "Remediation created successfully.",
            "success"
        )


        return redirect(
            url_for(
                "remediation.view_remediation",
                id=item.id
            )
        )


    # ======================================================
    # GET
    # ======================================================

    return render_template(

        "create_remediation.html",

        assets=assets,

        scans=scans

    )


# ==========================================================
# View Remediation
# ==========================================================

@remediation_bp.route(
    "/remediation/<int:id>",
    methods=["GET"]
)
@login_required
def view_remediation(id):

    item = Remediation.query.get_or_404(
        id
    )


    return render_template(

        "remediation_detail.html",

        remediation=item

    )


# ==========================================================
# Update Status
# ==========================================================

@remediation_bp.route(
    "/remediation/<int:id>/status",
    methods=["POST"]
)
@login_required
def update_status(id):

    item = Remediation.query.get_or_404(
        id
    )


    if current_user.role not in [
        "Admin",
        "Analyst"
    ]:

        flash(
            "You do not have permission to update remediation.",
            "danger"
        )

        return redirect(
            url_for(
                "remediation.view_remediation",
                id=id
            )
        )


    new_status = (
        request.form.get(
            "status",
            ""
        ).strip()
    )


    allowed_statuses = [
        "Open",
        "Assigned",
        "In Progress",
        "Remediated",
        "Verified",
        "Closed"
    ]


    if new_status not in allowed_statuses:

        flash(
            "Invalid remediation status.",
            "danger"
        )

        return redirect(
            url_for(
                "remediation.view_remediation",
                id=id
            )
        )


    old_status = item.status

    item.status = new_status


    if new_status == "Verified":

        item.verified_at = datetime.utcnow()


    db.session.commit()


    log_action(
        "REMEDIATION_STATUS_UPDATED",
        (
            f"Remediation {item.remediation_id} "
            f"status changed from "
            f"{old_status} to {new_status}."
        )
    )


    flash(
        "Remediation status updated.",
        "success"
    )


    return redirect(
        url_for(
            "remediation.view_remediation",
            id=id
        )
    )


# ==========================================================
# Assign Remediation
# ==========================================================

@remediation_bp.route(
    "/remediation/<int:id>/assign",
    methods=["POST"]
)
@login_required
def assign_remediation(id):

    item = Remediation.query.get_or_404(
        id
    )


    if current_user.role not in [
        "Admin",
        "Analyst"
    ]:

        flash(
            "You do not have permission to assign remediation.",
            "danger"
        )

        return redirect(
            url_for(
                "remediation.view_remediation",
                id=id
            )
        )


    assigned_to = (
        request.form.get(
            "assigned_to",
            ""
        ).strip()
    )


    if not assigned_to:

        flash(
            "Please provide an analyst name.",
            "danger"
        )

        return redirect(
            url_for(
                "remediation.view_remediation",
                id=id
            )
        )


    item.assigned_to = assigned_to


    if item.status == "Open":

        item.status = "Assigned"


    db.session.commit()


    log_action(
        "REMEDIATION_ASSIGNED",
        (
            f"Remediation {item.remediation_id} "
            f"assigned to {assigned_to}."
        )
    )


    flash(
        "Remediation assigned successfully.",
        "success"
    )


    return redirect(
        url_for(
            "remediation.view_remediation",
            id=id
        )
    )


# ==========================================================
# Update Notes
# ==========================================================

@remediation_bp.route(
    "/remediation/<int:id>/notes",
    methods=["POST"]
)
@login_required
def update_notes(id):

    item = Remediation.query.get_or_404(
        id
    )


    if current_user.role not in [
        "Admin",
        "Analyst"
    ]:

        flash(
            "You do not have permission to update notes.",
            "danger"
        )

        return redirect(
            url_for(
                "remediation.view_remediation",
                id=id
            )
        )


    item.notes = (
        request.form.get(
            "notes",
            ""
        ).strip()
    )


    item.verification_notes = (
        request.form.get(
            "verification_notes",
            ""
        ).strip()
    )


    db.session.commit()


    log_action(
        "REMEDIATION_NOTES_UPDATED",
        (
            f"Notes updated for "
            f"remediation {item.remediation_id}."
        )
    )


    flash(
        "Remediation notes saved.",
        "success"
    )


    return redirect(
        url_for(
            "remediation.view_remediation",
            id=id
        )
    )


# ==========================================================
# Delete Remediation
# ==========================================================

@remediation_bp.route(
    "/remediation/<int:id>/delete",
    methods=["POST"]
)
@login_required
def delete_remediation(id):

    item = Remediation.query.get_or_404(
        id
    )


    if current_user.role != "Admin":

        flash(
            "Only administrators can delete remediation records.",
            "danger"
        )

        return redirect(
            url_for(
                "remediation.view_remediation",
                id=id
            )
        )


    remediation_id = item.remediation_id


    db.session.delete(
        item
    )

    db.session.commit()


    log_action(
        "REMEDIATION_DELETED",
        (
            f"Remediation deleted: "
            f"{remediation_id}"
        )
    )


    flash(
        "Remediation deleted successfully.",
        "success"
    )


    return redirect(
        url_for(
            "remediation.remediation"
        )
    )