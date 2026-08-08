from flask import Blueprint, render_template, flash
from flask_login import login_required

from forms.cve_form import CVEForm
from services.cve_service import search_cves


# ==========================================================
# CVE Intelligence Blueprint
# ==========================================================

cve_bp = Blueprint(
    "cve",
    __name__
)


# ==========================================================
# CVE Intelligence
# ==========================================================

@cve_bp.route("/cve", methods=["GET", "POST"])
@login_required
def cve():

    form = CVEForm()

    results = []

    keyword = ""

    if form.validate_on_submit():

        keyword = form.keyword.data.strip()

        results = search_cves(keyword)

        if not results:

            flash(
                "No CVE results were found for the given search.",
                "warning"
            )

    return render_template(
        "cve.html",
        form=form,
        results=results,
        keyword=keyword
    )