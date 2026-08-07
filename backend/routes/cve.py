from flask import Blueprint, render_template
from flask_login import login_required

from forms.cve_form import CVEForm
from services.cve_service import search_cves

cve_bp = Blueprint("cve", __name__)


@cve_bp.route("/cve", methods=["GET", "POST"])
@login_required
def cve():

    form = CVEForm()

    results = []

    if form.validate_on_submit():

        keyword = form.keyword.data

        results = search_cves(keyword)

    return render_template(
        "cve.html",
        form=form,
        results=results
    )