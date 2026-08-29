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
from models.remediation import Remediation

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
# Generate Remediation ID
# ==========================================================

def generate_remediation_id():

    last_remediation = Remediation.query.order_by(
        Remediation.id.desc()
    ).first()

    if last_remediation:

        next_number = (
            last_remediation.id + 1
        )

    else:

        next_number = 1

    return f"REM-{next_number:04d}"


# ==========================================================
# Severity Normalization
# ==========================================================

def normalize_severity(severity):

    severity = str(
        severity or "Medium"
    ).strip().capitalize()

    if severity not in [
        "Critical",
        "High",
        "Medium",
        "Low"
    ]:

        severity = "Medium"

    return severity


# ==========================================================
# Create Remediation From Incident
# ==========================================================

def create_incident_remediation(incident):

    # ------------------------------------------------------
    # Check for existing remediation
    #
    # Prevent duplicate remediation tasks.
    # ------------------------------------------------------

    existing = Remediation.query.filter_by(
        incident_id=incident.id
    ).first()

    if existing:

        print(
            f"[REMEDIATION] Existing remediation "
            f"{existing.remediation_id} found for "
            f"{incident.incident_id}"
        )

        return existing


    # ------------------------------------------------------
    # Normalize severity
    # ------------------------------------------------------

    severity = normalize_severity(
        incident.severity
    )


    # ------------------------------------------------------
    # Build description
    # ------------------------------------------------------

    description = (
        f"Remediation required for security incident "
        f"{incident.incident_id}.\n\n"
        f"Incident Title: {incident.title}\n"
        f"Severity: {severity}\n"
        f"Affected Asset: "
        f"{incident.asset or 'Not specified'}\n\n"
        f"Incident Description:\n"
        f"{incident.description or 'No description provided.'}"
    )


    # ------------------------------------------------------
    # Build recommendation
    # ------------------------------------------------------

    recommendation = (
        f"Investigate and resolve incident "
        f"{incident.incident_id}. "
        f"Review the affected asset, identify the root "
        f"cause, apply the required security controls or "
        f"patches, validate that the threat has been "
        f"removed, and perform a follow-up security check."
    )


    if severity in [
        "Critical",
        "High"
    ]:

        recommendation += (
            " This is a high-priority security issue and "
            "should be addressed as soon as possible."
        )


    # ------------------------------------------------------
    # Create remediation
    # ------------------------------------------------------

    remediation = Remediation(

        remediation_id=generate_remediation_id(),

        title=(
            f"Resolve {incident.incident_id}: "
            f"{incident.title}"
        ),

        cve_id=None,

        asset_id=None,

        scan_id=None,

        incident_id=incident.id,

        severity=severity,

        description=description,

        recommendation=recommendation,

        status="Open",

        assigned_to=(
            incident.assigned_to
            if incident.assigned_to
            else None
        ),

        notes=(
            f"Automatically generated from "
            f"{incident.incident_id}."
        )

    )


    # ------------------------------------------------------
    # Save remediation
    # ------------------------------------------------------

    db.session.add(
        remediation
    )

    db.session.flush()


    # ------------------------------------------------------
    # Audit log
    # ------------------------------------------------------

    log_action(
        "REMEDIATION_AUTO_CREATED",
        (
            f"Remediation automatically created "
            f"from incident. "
            f"Remediation: "
            f"{remediation.remediation_id}. "
            f"Incident: {incident.incident_id}. "
            f"Severity: {severity}. "
            f"Asset: "
            f"{incident.asset or 'Not specified'}."
        )
    )


    print(
        f"[REMEDIATION] Created "
        f"{remediation.remediation_id} "
        f"for incident "
        f"{incident.incident_id}"
    )


    return remediation


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
                url_for(
                    "incidents.incidents"
                )
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
                f"INC-{incident_number:04d}"
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
                normalize_severity(
                    form.severity.data
                )
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


        try:

            db.session.flush()


            # ==================================================
            # Automatic Incident Remediation
            # ==================================================

            remediation = (
                create_incident_remediation(
                    incident
                )
            )


            # --------------------------------------------------
            # Commit Incident + Remediation
            # --------------------------------------------------

            db.session.commit()


        except Exception as error:

            db.session.rollback()


            log_action(
                "INCIDENT_CREATE_FAILED",
                (
                    f"Failed to create incident or "
                    f"automatic remediation. "
                    f"Error: {str(error)}"
                )
            )


            flash(
                (
                    "Unable to create the incident. "
                    "Please check the server logs."
                ),
                "danger"
            )


            return redirect(
                url_for(
                    "incidents.incidents"
                )
            )


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


        # ==================================================
        # Success Message
        # ==================================================

        flash(
            (
                f"Incident {incident.incident_id} "
                f"created successfully. "
                f"Remediation "
                f"{remediation.remediation_id} "
                f"was created automatically."
            ),
            "success"
        )


        return redirect(
            url_for(
                "incidents.incidents"
            )
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
    # Remediation Statistics
    # ======================================================

    total_remediations = Remediation.query.count()


    open_remediations = Remediation.query.filter_by(
        status="Open"
    ).count()


    critical_remediations = Remediation.query.filter_by(
        severity="Critical"
    ).count()


    high_remediations = Remediation.query.filter_by(
        severity="High"
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

        low_incidents=low_incidents,

        total_remediations=total_remediations,

        open_remediations=open_remediations,

        critical_remediations=critical_remediations,

        high_remediations=high_remediations

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
    # Delete Related Remediations First
    #
    # This prevents foreign-key problems when deleting
    # an incident that has remediation records.
    # ------------------------------------------------------

    related_remediations = Remediation.query.filter_by(
        incident_id=incident.id
    ).all()


    for remediation in related_remediations:

        db.session.delete(
            remediation
        )


    # ------------------------------------------------------
    # Delete Incident
    # ------------------------------------------------------

    db.session.delete(
        incident
    )


    try:

        db.session.commit()

    except Exception as error:

        db.session.rollback()


        log_action(
            "INCIDENT_DELETE_FAILED",
            (
                f"Failed to delete incident "
                f"{incident_id}. "
                f"Error: {str(error)}"
            )
        )


        flash(
            "Unable to delete incident.",
            "danger"
        )


        return redirect(
            url_for(
                "incidents.incidents"
            )
        )


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
        "Incident and related remediation(s) deleted successfully!",
        "success"
    )


    return redirect(
        url_for(
            "incidents.incidents"
        )
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
            normalize_severity(
                form.severity.data
            )
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
        # Update Related Remediation
        #
        # Keep the automatically created remediation
        # synchronized with important incident changes.
        # --------------------------------------------------

        related_remediations = Remediation.query.filter_by(
            incident_id=incident.id
        ).all()


        for remediation in related_remediations:

            remediation.severity = (
                incident.severity
            )

            remediation.assigned_to = (
                incident.assigned_to
                if incident.assigned_to
                else None
            )

            remediation.description = (
                f"Remediation required for security incident "
                f"{incident.incident_id}.\n\n"
                f"Incident Title: {incident.title}\n"
                f"Severity: {incident.severity}\n"
                f"Affected Asset: "
                f"{incident.asset or 'Not specified'}\n\n"
                f"Incident Description:\n"
                f"{incident.description or 'No description provided.'}"
            )


        # --------------------------------------------------
        # Save Changes
        # --------------------------------------------------

        try:

            db.session.commit()

        except Exception as error:

            db.session.rollback()


            log_action(
                "INCIDENT_UPDATE_FAILED",
                (
                    f"Failed to update incident "
                    f"{incident.incident_id}. "
                    f"Error: {str(error)}"
                )
            )


            flash(
                "Unable to update incident.",
                "danger"
            )


            return redirect(
                url_for(
                    "incidents.incidents"
                )
            )


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
            url_for(
                "incidents.incidents"
            )
        )


    # ======================================================
    # Edit Page
    # ======================================================

    return render_template(

        "edit_incident.html",

        form=form,

        incident=incident

    )