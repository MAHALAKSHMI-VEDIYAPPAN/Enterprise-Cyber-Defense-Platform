from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required

from extensions import db
from models.scan import Scan
from forms.scan_form import ScanForm
from services.scanner_service import run_scan

scanner_bp = Blueprint("scanner", __name__)


# ==========================================================
# Vulnerability Scanner
# ==========================================================
@scanner_bp.route("/scanner", methods=["GET", "POST"])
@login_required
def scanner():

    form = ScanForm()

    if form.validate_on_submit():

        target = form.target.data.strip()

        # Run Real Nmap Scan
        result = run_scan(target)

        scan = Scan(
            target=target,
            open_ports=result["open_ports"],
            services=result["services"],
            status=result["status"]
        )

        db.session.add(scan)
        db.session.commit()

        flash("Scan completed successfully!", "success")

        return redirect(url_for("scanner.scanner"))

    scans = Scan.query.order_by(Scan.id.desc()).all()

    return render_template(
        "scanner.html",
        form=form,
        scans=scans
    )