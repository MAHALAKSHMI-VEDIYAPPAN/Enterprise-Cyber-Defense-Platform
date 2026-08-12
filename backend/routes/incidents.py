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

from models.incident import Incident

from forms.incident_form import IncidentForm

from utils.decorators import role_required

from utils.audit_logger import log_action


# ==========================================================
# Incident Management Blueprint
# ==========================================================

incidents_bp = Blueprint(
    "incidents",
    __name__
)


# ==========================================================
# Incident Management
# ==========================================================

@incidents_bp.route(
    "/incidents",
    methods=["GET", "POST"]
)
@login_required
def incidents():

    form = IncidentForm()


    # ======================================================
    # Create New Incident
    # ======================================================

    if form.validate_on_submit():

        # --------------------------------------------------
        # Role Check
        # --------------------------------------------------

        if current_user.role not in [
            "Admin",
            "Analyst"
        ]:

            flash(
                "You do not have permission to create incidents.",
                "danger"
            )

            return redirect(
                url_for("incidents.incidents")
            )


        # --------------------------------------------------
        # Generate Incident ID
        # --------------------------------------------------

        last_incident = Incident.query.order_by(
            Incident.id.desc()
        ).first()


        if last_incident:

            incident_number = (
                last_incident.id + 1
            )

        else:

            incident_number = 1


        # --------------------------------------------------
        # Create Incident
        # --------------------------------------------------

        incident = Incident(

            incident_id=(
                f"INC-{incident_number:04}"
            ),

            title=(
                form.title.data.strip()
            ),

            asset=(
                form.asset.data.strip()
                if form.asset.data
                else ""
            ),

            severity=(
                form.severity.data
            ),

            assigned_to=(
                form.assigned_to.data.strip()
                if form.assigned_to.data
                else ""
            ),

            description=(
                form.description.data.strip()
                if form.description.data
                else ""
            ),

            status="Open"

        )


        # --------------------------------------------------
        # Save Incident
        # --------------------------------------------------

        db.session.add(
            incident
        )

        db.session.commit()


        # ==================================================
        # Audit Log
        # ==================================================

        log_action(
            "INCIDENT_CREATED",
            (
                f"Incident created: "
                f"{incident.incident_id} - "
                f"{incident.title}. "
                f"Severity: {incident.severity}. "
                f"Asset: {incident.asset}"
            )
        )


        # --------------------------------------------------
        # Success Message
        # --------------------------------------------------

        flash(
            "Incident created successfully!",
            "success"
        )


        return redirect(
            url_for("incidents.incidents")
        )


    # ======================================================
    # Search
    # ======================================================

    search = request.args.get(
        "search",
        ""
    ).strip()


    if search:

        search_pattern = (
            f"%{search}%"
        )


        incident_list = Incident.query.filter(

            db.or_(

                Incident.incident_id.ilike(
                    search_pattern
                ),

                Incident.title.ilike(
                    search_pattern
                ),

                Incident.asset.ilike(
                    search_pattern
                ),

                Incident.severity.ilike(
                    search_pattern
                ),

                Incident.status.ilike(
                    search_pattern
                ),

                Incident.assigned_to.ilike(
                    search_pattern
                )

            )

        ).order_by(

            Incident.created_at.desc()

        ).all()


    else:

        incident_list = Incident.query.order_by(

            Incident.created_at.desc()

        ).all()


    # ======================================================
    # Incident Statistics
    # ======================================================

    total_incidents = Incident.query.count()


    open_incidents = Incident.query.filter_by(
        status="Open"
    ).count()


    in_progress_incidents = Incident.query.filter_by(
        status="In Progress"
    ).count()


    resolved_incidents = Incident.query.filter_by(
        status="Resolved"
    ).count()


    closed_incidents = Incident.query.filter_by(
        status="Closed"
    ).count()


    # ======================================================
    # Severity Statistics
    # ======================================================

    critical_incidents = Incident.query.filter_by(
        severity="Critical"
    ).count()


    high_incidents = Incident.query.filter_by(
        severity="High"
    ).count()


    medium_incidents = Incident.query.filter_by(
        severity="Medium"
    ).count()


    low_incidents = Incident.query.filter_by(
        severity="Low"
    ).count()


    # ======================================================
    # Render Incident Dashboard
    # ======================================================

    return render_template(

        "incidents.html",

        form=form,

        incidents=incident_list,

        search=search,

        total_incidents=total_incidents,

        open_incidents=open_incidents,

        in_progress_incidents=in_progress_incidents,

        resolved_incidents=resolved_incidents,

        closed_incidents=closed_incidents,

        critical_incidents=critical_incidents,

        high_incidents=high_incidents,

        medium_incidents=medium_incidents,

        low_incidents=low_incidents

    )


# ==========================================================
# Delete Incident
# ==========================================================

@incidents_bp.route(
    "/delete_incident/<int:id>",
    methods=["POST"]
)
@login_required
@role_required("Admin")
def delete_incident(id):

    incident = Incident.query.get_or_404(
        id
    )


    # ------------------------------------------------------
    # Save Details Before Deletion
    # ------------------------------------------------------

    incident_id = incident.incident_id

    incident_title = incident.title

    incident_severity = incident.severity


    # ------------------------------------------------------
    # Delete Incident
    # ------------------------------------------------------

    db.session.delete(
        incident
    )

    db.session.commit()


    # ======================================================
    # Audit Log
    # ======================================================

    log_action(
        "INCIDENT_DELETED",
        (
            f"Incident deleted: "
            f"{incident_id} - "
            f"{incident_title}. "
            f"Severity: {incident_severity}"
        )
    )


    # ------------------------------------------------------
    # Success Message
    # ------------------------------------------------------

    flash(
        "Incident deleted successfully!",
        "success"
    )


    return redirect(
        url_for("incidents.incidents")
    )


# ==========================================================
# Edit Incident
# ==========================================================

@incidents_bp.route(
    "/edit_incident/<int:id>",
    methods=["GET", "POST"]
)
@login_required
@role_required(
    "Admin",
    "Analyst"
)
def edit_incident(id):

    incident = Incident.query.get_or_404(
        id
    )


    form = IncidentForm(
        obj=incident
    )


    # ======================================================
    # Update Incident
    # ======================================================

    if form.validate_on_submit():

        # --------------------------------------------------
        # Store Previous Values
        # --------------------------------------------------

        old_title = incident.title

        old_severity = incident.severity

        old_asset = incident.asset

        old_assigned_to = incident.assigned_to


        # --------------------------------------------------
        # Update Title
        # --------------------------------------------------

        incident.title = (

            form.title.data.strip()

            if form.title.data

            else ""

        )


        # --------------------------------------------------
        # Update Asset
        # --------------------------------------------------

        incident.asset = (

            form.asset.data.strip()

            if form.asset.data

            else ""

        )


        # --------------------------------------------------
        # Update Severity
        # --------------------------------------------------

        incident.severity = (
            form.severity.data
        )


        # --------------------------------------------------
        # Update Assigned User
        # --------------------------------------------------

        incident.assigned_to = (

            form.assigned_to.data.strip()

            if form.assigned_to.data

            else ""

        )


        # --------------------------------------------------
        # Update Description
        # --------------------------------------------------

        incident.description = (

            form.description.data.strip()

            if form.description.data

            else ""

        )


        # --------------------------------------------------
        # Save Changes
        # --------------------------------------------------

        db.session.commit()


        # ==================================================
        # Audit Log
        # ==================================================

        log_action(
            "INCIDENT_UPDATED",
            (
                f"Incident updated: "
                f"{incident.incident_id}. "
                f"Title: {old_title} -> "
                f"{incident.title}. "
                f"Severity: {old_severity} -> "
                f"{incident.severity}. "
                f"Asset: {old_asset} -> "
                f"{incident.asset}. "
                f"Assigned To: {old_assigned_to} -> "
                f"{incident.assigned_to}"
            )
        )


        # --------------------------------------------------
        # Success Message
        # --------------------------------------------------

        flash(
            "Incident updated successfully!",
            "success"
        )


        return redirect(
            url_for("incidents.incidents")
        )


    # ======================================================
    # Edit Page
    # ======================================================

    return render_template(

        "edit_incident.html",

        form=form,

        incident=incident

    )