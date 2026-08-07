from flask import Blueprint, render_template, request
from flask_login import login_required

from services.threat_service import check_ip_reputation

threat_bp = Blueprint("threat", __name__)


@threat_bp.route("/threat", methods=["GET", "POST"])
@login_required
def threat():

    result = None

    if request.method == "POST":

        ip = request.form.get("ip")

        result = check_ip_reputation(ip)

    return render_template(
        "threat.html",
        result=result
    )