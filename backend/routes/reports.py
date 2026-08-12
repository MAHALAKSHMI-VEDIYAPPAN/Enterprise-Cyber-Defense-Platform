from flask import Blueprint, render_template, send_file
from flask_login import login_required

from services.report_service import generate_security_report
from services.pdf_service import generate_security_pdf


# ==========================================================
# Reports Blueprint
# ==========================================================

reports_bp = Blueprint(
    "reports",
    __name__
)


# ==========================================================
# Security Reports Page
# ==========================================================

@reports_bp.route("/reports")
@login_required
def reports():

    report = generate_security_report()

    return render_template(
        "reports.html",
        report=report
    )


# ==========================================================
# Generate PDF Security Report
# ==========================================================

@reports_bp.route("/reports/pdf")
@login_required
def reports_pdf():

    report = generate_security_report()

    pdf_file = generate_security_pdf(report)

    return send_file(
        pdf_file,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="ECDP_Security_Report.pdf"
    )