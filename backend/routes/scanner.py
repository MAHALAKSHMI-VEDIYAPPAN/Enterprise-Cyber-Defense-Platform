from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required

from extensions import db
from models.scan import Scan
from forms.scan_form import ScanForm
from services.scanner_service import run_scan


# ==========================================================
# Vulnerability Scanner Blueprint
# ==========================================================

scanner_bp = Blueprint(
    "scanner",
    __name__
)


# ==========================================================
# Vulnerability Scanner
# ==========================================================

@scanner_bp.route("/scanner", methods=["GET", "POST"])
@login_required
def scanner():

    form = ScanForm()

    if form.validate_on_submit():

        target = form.target.data.strip()

        # ------------------------------------------
        # Run Nmap Scan
        # ------------------------------------------

        result = run_scan(target)

        # ------------------------------------------
        # Store Scan Result
        # ------------------------------------------

        scan = Scan(
            target=target,
            open_ports=result["open_ports"],
            services=result["services"],
            status=result["status"]
        )

        db.session.add(scan)
        db.session.commit()

        # ------------------------------------------
        # User Feedback
        # ------------------------------------------

        if result["status"] == "Completed":

            flash(
                f"Scan completed successfully for {target}.",
                "success"
            )

        elif result["status"] == "Host Down":

            flash(
                f"The target {target} could not be detected.",
                "warning"
            )

        else:

            flash(
                f"Scan failed for {target}.",
                "danger"
            )

        return redirect(
            url_for("scanner.scanner")
        )

    # ------------------------------------------
    # Scan History
    # ------------------------------------------

    scans = Scan.query.order_by(
        Scan.scan_date.desc()
    ).all()

    return render_template(
        "scanner.html",
        form=form,
        scans=scans
    )