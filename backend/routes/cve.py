from flask import (
    Blueprint,
    render_template,
    flash
)

from flask_login import (
    login_required,
    current_user
)

from forms.cve_form import CVEForm

from services.cve_service import (
    search_cves,
    get_cve_details
)

from utils.audit_logger import log_action


# ==========================================================
# CVE Intelligence Blueprint
# ==========================================================

cve_bp = Blueprint(
    "cve",
    __name__
)


# ==========================================================
# CVE Search
# ==========================================================

@cve_bp.route(
    "/cve",
    methods=["GET", "POST"]
)
@login_required
def cve():

    form = CVEForm()

    results = []

    keyword = ""


    # ======================================================
    # CVE Search
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
                "You do not have permission to search CVEs.",
                "danger"
            )

            return render_template(
                "cve.html",
                form=form,
                results=[],
                keyword=""
            )


        # --------------------------------------------------
        # Get Search Keyword
        # --------------------------------------------------

        keyword = (
            form.keyword.data.strip()
        )


        # ==================================================
        # Audit - Search Started
        # ==================================================

        log_action(
            "CVE_SEARCH_STARTED",
            (
                f"CVE search started for keyword: "
                f"{keyword}"
            )
        )


        # ==================================================
        # Search NVD
        # ==================================================

        try:

            results = search_cves(
                keyword
            )


        except Exception as error:

            print(
                "CVE SEARCH ERROR:",
                error
            )


            log_action(
                "CVE_SEARCH_FAILED",
                (
                    f"CVE search failed for: "
                    f"{keyword}"
                )
            )


            results = []


            flash(
                "Unable to retrieve CVE information "
                "from NVD at this time.",
                "danger"
            )


        # ==================================================
        # Search Completed
        # ==================================================

        if results:

            log_action(
                "CVE_SEARCH_COMPLETED",
                (
                    f"CVE search completed for: "
                    f"{keyword}. "
                    f"Results returned: "
                    f"{len(results)}."
                )
            )


        # ==================================================
        # No Results
        # ==================================================

        else:

            flash(
                "No CVE results were found for "
                "the given search.",
                "warning"
            )


            log_action(
                "CVE_SEARCH_NO_RESULTS",
                (
                    f"No CVE results found for: "
                    f"{keyword}"
                )
            )


    # ======================================================
    # Render Search Page
    # ======================================================

    return render_template(
        "cve.html",
        form=form,
        results=results,
        keyword=keyword
    )


# ==========================================================
# CVE Details
# ==========================================================

@cve_bp.route(
    "/cve/details/<string:cve_id>",
    methods=["GET"]
)
@login_required
def cve_details(cve_id):

    # ======================================================
    # Role Check
    # ======================================================

    if current_user.role not in [
        "Admin",
        "Analyst",
        "Viewer"
    ]:

        flash(
            "You do not have permission to view "
            "CVE details.",
            "danger"
        )

        return render_template(
            "cve_details.html",
            cve=None,
            error="Access denied.",
            cve_id=cve_id,
            nvd_url=(
                "https://nvd.nist.gov/vuln/detail/"
                f"{cve_id.upper()}"
            )
        )


    # ======================================================
    # Validate CVE ID
    # ======================================================

    cve_id = (
        cve_id or ""
    ).strip().upper()


    if not cve_id.startswith("CVE-"):

        flash(
            "Invalid CVE identifier.",
            "danger"
        )

        return render_template(
            "cve_details.html",
            cve=None,
            error="Invalid CVE identifier.",
            cve_id=cve_id,
            nvd_url=(
                "https://nvd.nist.gov/vuln/detail/"
                f"{cve_id}"
            )
        )


    # ======================================================
    # Audit - Details Requested
    # ======================================================

    log_action(
        "CVE_DETAILS_VIEWED",
        (
            f"CVE details requested for "
            f"{cve_id}."
        )
    )


    # ======================================================
    # Get Complete CVE Information
    #
    # The service already:
    # - Calls NVD
    # - Extracts description
    # - Extracts CVSS
    # - Extracts CWE
    # - Extracts references
    # - Extracts affected products
    # - Generates NVD URL
    # - Gets NVD change history
    # ======================================================

    try:

        cve = get_cve_details(
            cve_id
        )


    except Exception as error:

        print(
            "CVE DETAILS ERROR:",
            error
        )

        cve = None


    # ======================================================
    # CVE Not Found / API Failure
    # ======================================================

    if not cve:

        log_action(
            "CVE_DETAILS_FAILED",
            (
                f"Unable to retrieve details "
                f"for {cve_id}."
            )
        )


        return render_template(
            "cve_details.html",
            cve=None,
            error=(
                "Unable to retrieve this CVE from "
                "the NVD database. The CVE may not "
                "exist, or the NVD API may currently "
                "be unavailable."
            ),
            cve_id=cve_id,
            nvd_url=(
                "https://nvd.nist.gov/vuln/detail/"
                f"{cve_id}"
            )
        )


    # ======================================================
    # Make Sure NVD URL Exists
    # ======================================================

    if not cve.get("reference"):

        cve["reference"] = (
            "https://nvd.nist.gov/vuln/detail/"
            f"{cve_id}"
        )


    # ======================================================
    # Compatibility Fields
    #
    # This allows cve_details.html to use either
    # naming style without breaking.
    # ======================================================

    cve["nvd_url"] = (
        cve.get("nvd_url")
        or cve.get("reference")
        or (
            "https://nvd.nist.gov/vuln/detail/"
            f"{cve_id}"
        )
    )


    # ======================================================
    # Audit - Details Loaded
    # ======================================================

    log_action(
        "CVE_DETAILS_LOADED",
        (
            f"CVE details successfully loaded: "
            f"{cve_id}. "
            f"CVSS: {cve.get('score', 'N/A')}. "
            f"Severity: {cve.get('severity', 'N/A')}."
        )
    )


    # ======================================================
    # Render Complete Details
    # ======================================================

    return render_template(
        "cve_details.html",
        cve=cve,
        error=None,
        cve_id=cve_id,
        nvd_url=cve["nvd_url"]
    )