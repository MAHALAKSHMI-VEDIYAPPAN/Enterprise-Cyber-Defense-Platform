from flask import Blueprint, render_template, request, flash
from flask_login import login_required

from services.threat_service import check_ip_reputation


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

@threat_bp.route("/threat", methods=["GET", "POST"])
@login_required
def threat():

    result = None
    ip_address = ""

    if request.method == "POST":

        ip_address = request.form.get("ip", "").strip()

        if not ip_address:

            flash(
                "Please enter an IP address.",
                "warning"
            )

        else:

            result = check_ip_reputation(ip_address)

    return render_template(
        "threat.html",
        result=result,
        ip_address=ip_address
    )