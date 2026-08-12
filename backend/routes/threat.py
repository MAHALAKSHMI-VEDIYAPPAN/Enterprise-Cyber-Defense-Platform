from flask import (
    Blueprint,
    render_template,
    flash
)

from flask_login import (
    login_required,
    current_user
)

from forms.threat_form import ThreatForm

from services.threat_service import check_ip_reputation

from utils.audit_logger import log_action


# ==========================================================
# Threat Intelligence Blueprint
# ==========================================================

threat_bp = Blueprint(
    "threat",
    __name__
)


# ==========================================================
# Threat Intelligence
# ==========================================================

@threat_bp.route(
    "/threat",
    methods=["GET", "POST"]
)
@login_required
def threat():

    form = ThreatForm()

    result = None

    ip_address = ""


    # ======================================================
    # Threat Analysis
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
                "You do not have permission to perform "
                "threat intelligence analysis.",
                "danger"
            )

            return render_template(
                "threat.html",
                form=form,
                result=None,
                ip_address=""
            )


        # --------------------------------------------------
        # Get Submitted IP
        # --------------------------------------------------

        ip_address = (
            form.ip.data.strip()
        )


        # ==================================================
        # Audit - Analysis Started
        # ==================================================

        log_action(
            "THREAT_ANALYSIS_STARTED",
            (
                f"Threat intelligence analysis started "
                f"for IP address {ip_address}."
            )
        )


        # ==================================================
        # Perform Threat Analysis
        # ==================================================

        try:

            result = check_ip_reputation(
                ip_address
            )

        except Exception:

            # --------------------------------------------------
            # Audit - Analysis Failed
            # --------------------------------------------------

            log_action(
                "THREAT_ANALYSIS_FAILED",
                (
                    f"Threat intelligence analysis failed "
                    f"for IP address {ip_address}."
                )
            )


            flash(
                "Threat analysis failed.",
                "danger"
            )


            return render_template(
                "threat.html",
                form=form,
                result=None,
                ip_address=ip_address
            )


        # ==================================================
        # Handle Analysis Result
        # ==================================================

        if result and result.get("success"):

            # --------------------------------------------------
            # Audit - Analysis Completed
            # --------------------------------------------------

            log_action(
                "THREAT_ANALYSIS_COMPLETED",
                (
                    f"Threat intelligence analysis completed "
                    f"for IP address {ip_address}."
                )
            )

        else:

            # --------------------------------------------------
            # Audit - Analysis Failed
            # --------------------------------------------------

            log_action(
                "THREAT_ANALYSIS_FAILED",
                (
                    f"Threat intelligence analysis returned "
                    f"an unsuccessful result for "
                    f"IP address {ip_address}."
                )
            )


            flash(
                result.get(
                    "message",
                    "Threat analysis failed."
                ),
                "danger"
            )


    # ======================================================
    # Preserve Submitted IP
    # ======================================================

    elif form.ip.data:

        ip_address = (
            form.ip.data.strip()
        )


    # ======================================================
    # Render Page
    # ======================================================

    return render_template(
        "threat.html",
        form=form,
        result=result,
        ip_address=ip_address
    )