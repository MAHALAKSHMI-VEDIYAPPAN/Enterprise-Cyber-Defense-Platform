from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required

from extensions import db
from models.scan import Scan
from forms.scan_form import ScanForm

scanner_bp = Blueprint("scanner", __name__)


@scanner_bp.route("/scanner", methods=["GET", "POST"])
@login_required
def scanner():

    form = ScanForm()

    if form.validate_on_submit():

        scan = Scan(
            target=form.target.data,
            open_ports="Pending...",
            services="Pending..."
        )

        db.session.add(scan)
        db.session.commit()

        flash("Scan request saved successfully!")

        return redirect(url_for("scanner.scanner"))

    scans = Scan.query.order_by(Scan.id.desc()).all()

    return render_template(
        "scanner.html",
        form=form,
        scans=scans
    )