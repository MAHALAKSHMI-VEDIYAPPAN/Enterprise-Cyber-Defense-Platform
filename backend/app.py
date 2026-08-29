import os
import json

from flask import (
    Flask,
    render_template
)

from flask_login import login_required

from config import Config

from extensions import (
    db,
    login_manager
)


# ==========================================================
# Blueprints
# ==========================================================

from routes.auth import auth_bp
from routes.assets import assets_bp
from routes.scanner import scanner_bp
from routes.threat import threat_bp
from routes.incidents import incidents_bp
from routes.cve import cve_bp
from routes.reports import reports_bp
from routes.ai_security import ai_security_bp
from routes.security_chat import security_chat_bp
from routes.remediation import remediation_bp

# Audit Logs Blueprint
from routes.audit import audit_bp


# ==========================================================
# Models
# ==========================================================

from models.asset import Asset
from models.scan import Scan
from models.incident import Incident
from models.audit_log import AuditLog
from models.remediation import Remediation


# ==========================================================
# Services
# ==========================================================

from services.report_service import calculate_security_score


# ==========================================================
# Create Flask Application
# ==========================================================

app = Flask(
    __name__
)


# ==========================================================
# Load Configuration
# ==========================================================

app.config.from_object(
    Config
)


# ==========================================================
# Security Headers
# ==========================================================

@app.after_request
def add_security_headers(response):

    # ------------------------------------------------------
    # Prevent MIME-Type Sniffing
    # ------------------------------------------------------

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"


    # ------------------------------------------------------
    # Clickjacking Protection
    # ------------------------------------------------------

    response.headers[
        "X-Frame-Options"
    ] = "SAMEORIGIN"


    # ------------------------------------------------------
    # Referrer Policy
    # ------------------------------------------------------

    response.headers[
        "Referrer-Policy"
    ] = "strict-origin-when-cross-origin"


    # ------------------------------------------------------
    # Browser Feature Restrictions
    # ------------------------------------------------------

    response.headers[
        "Permissions-Policy"
    ] = (
        "geolocation=(), "
        "microphone=(), "
        "camera=()"
    )


    # ------------------------------------------------------
    # Content Security Policy
    # ------------------------------------------------------

    response.headers[
        "Content-Security-Policy"
    ] = (
        "default-src 'self'; "

        "script-src "
        "'self' "
        "'unsafe-inline' "
        "https://cdn.jsdelivr.net; "

        "style-src "
        "'self' "
        "'unsafe-inline' "
        "https://cdn.jsdelivr.net; "

        "img-src "
        "'self' "
        "data: "
        "blob:; "

        "font-src "
        "'self' "
        "data: "
        "https://cdn.jsdelivr.net; "

        "connect-src "
        "'self'; "

        "frame-ancestors "
        "'self';"
    )


    return response


# ==========================================================
# Initialize Extensions
# ==========================================================

db.init_app(
    app
)

login_manager.init_app(
    app
)


# ==========================================================
# Register Blueprints
# ==========================================================

app.register_blueprint(
    auth_bp
)

app.register_blueprint(
    assets_bp
)

app.register_blueprint(
    scanner_bp
)

app.register_blueprint(
    threat_bp
)

app.register_blueprint(
    incidents_bp
)

app.register_blueprint(
    cve_bp
)

app.register_blueprint(
    reports_bp
)

app.register_blueprint(
    ai_security_bp
)

app.register_blueprint(
    security_chat_bp
)

app.register_blueprint(
    remediation_bp
)

# ==========================================================
# Audit Logs Blueprint
# ==========================================================

app.register_blueprint(
    audit_bp
)


# ==========================================================
# Home Page
# ==========================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ==========================================================
# Dashboard
# ==========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    # ======================================================
    # Asset Statistics
    # ======================================================

    total_assets = Asset.query.count()

    active_assets = Asset.query.filter_by(
        status="Active"
    ).count()

    high_risk_assets = Asset.query.filter(
        Asset.risk_level.in_(
            [
                "High",
                "Critical"
            ]
        )
    ).count()


    # ======================================================
    # Scan Statistics
    # ======================================================

    total_scans = Scan.query.count()

    completed_scans = Scan.query.filter_by(
        status="Completed"
    ).count()

    failed_scans = Scan.query.filter(
        Scan.status != "Completed"
    ).count()


    # ======================================================
    # Vulnerability Statistics
    # ======================================================

    total_vulnerabilities = 0

    critical_vulnerabilities = 0

    high_vulnerabilities = 0

    medium_vulnerabilities = 0

    low_vulnerabilities = 0

    highest_cvss = 0.0

    unique_cves = set()


    # ======================================================
    # Process Scan Results
    # ======================================================

    all_scans = Scan.query.all()

    for scan in all_scans:

        # --------------------------------------------------
        # Highest CVSS
        # --------------------------------------------------

        try:

            scan_cvss = float(
                scan.max_cvss or 0
            )

            if scan_cvss > highest_cvss:

                highest_cvss = scan_cvss

        except (
            TypeError,
            ValueError
        ):

            pass


        # --------------------------------------------------
        # Vulnerability JSON
        # --------------------------------------------------

        raw_vulnerabilities = (
            scan.vulnerabilities
            or "[]"
        )

        try:

            vulnerabilities = json.loads(
                raw_vulnerabilities
            )

        except (
            TypeError,
            ValueError,
            json.JSONDecodeError
        ):

            vulnerabilities = []


        if not isinstance(
            vulnerabilities,
            list
        ):

            vulnerabilities = []


        # --------------------------------------------------
        # Process Vulnerabilities
        # --------------------------------------------------

        for vulnerability in vulnerabilities:

            if not isinstance(
                vulnerability,
                dict
            ):

                continue


            total_vulnerabilities += 1


            # ------------------------------------------------
            # CVE
            # ------------------------------------------------

            cve_id = (
                vulnerability.get("id")
                or vulnerability.get("cve_id")
            )

            if cve_id:

                unique_cves.add(
                    str(cve_id).upper()
                )


            # ------------------------------------------------
            # Severity
            # ------------------------------------------------

            severity = str(
                vulnerability.get(
                    "severity",
                    ""
                )
            ).strip().upper()


            if severity == "CRITICAL":

                critical_vulnerabilities += 1

            elif severity == "HIGH":

                high_vulnerabilities += 1

            elif severity == "MEDIUM":

                medium_vulnerabilities += 1

            elif severity == "LOW":

                low_vulnerabilities += 1


    # ======================================================
    # Unique CVEs
    # ======================================================

    unique_cve_count = len(
        unique_cves
    )


    # ======================================================
    # Incident Statistics
    # ======================================================

    total_incidents = Incident.query.count()

    open_incidents = Incident.query.filter_by(
        status="Open"
    ).count()

    critical_incidents = Incident.query.filter(
        Incident.severity.in_(
            [
                "Critical",
                "High"
            ]
        )
    ).filter(
        Incident.status != "Closed"
    ).count()


    # ======================================================
    # Remediation Statistics
    # ======================================================

    total_remediations = Remediation.query.count()


    open_remediations = Remediation.query.filter_by(
        status="Open"
    ).count()


    in_progress_remediations = Remediation.query.filter_by(
        status="In Progress"
    ).count()


    verified_remediations = Remediation.query.filter_by(
        status="Verified"
    ).count()


    closed_remediations = Remediation.query.filter_by(
        status="Closed"
    ).count()


    # ======================================================
    # High / Critical Remediation Count
    # ======================================================

    high_priority_remediations = Remediation.query.filter(
        Remediation.severity.in_(
            [
                "High",
                "Critical"
            ]
        )
    ).filter(
        Remediation.status.notin_(
            [
                "Closed",
                "Verified"
            ]
        )
    ).count()


    # ======================================================
    # Remediation Completion
    # ======================================================

    completed_remediations = (
        verified_remediations
        + closed_remediations
    )


    if total_remediations > 0:

        remediation_completion = round(
            (
                completed_remediations
                / total_remediations
            ) * 100,
            1
        )

    else:

        remediation_completion = 0


    # ======================================================
    # Security Score
    # ======================================================

    security_score = calculate_security_score(

        total_assets=total_assets,

        high_risk_assets=high_risk_assets,

        total_incidents=total_incidents,

        critical_incidents=critical_incidents,

        open_incidents=open_incidents

    )


    # ======================================================
    # Recent Scans
    # ======================================================

    recent_scans = Scan.query.order_by(

        Scan.scan_date.desc()

    ).limit(
        5
    ).all()


    # ======================================================
    # Recent Incidents
    # ======================================================

    recent_incidents = Incident.query.order_by(

        Incident.created_at.desc()

    ).limit(
        5
    ).all()


    # ======================================================
    # Recent Audit Logs
    # ======================================================

    recent_audits = AuditLog.query.order_by(

        AuditLog.timestamp.desc()

    ).limit(
        10
    ).all()


    # ======================================================
    # Dashboard Debug Information
    # ======================================================

    print(
        "[DASHBOARD] Assets:",
        total_assets
    )

    print(
        "[DASHBOARD] Scans:",
        total_scans
    )

    print(
        "[DASHBOARD] Vulnerabilities:",
        total_vulnerabilities
    )

    print(
        "[DASHBOARD] Unique CVEs:",
        unique_cve_count
    )

    print(
        "[DASHBOARD] Critical:",
        critical_vulnerabilities
    )

    print(
        "[DASHBOARD] High:",
        high_vulnerabilities
    )

    print(
        "[DASHBOARD] Medium:",
        medium_vulnerabilities
    )

    print(
        "[DASHBOARD] Low:",
        low_vulnerabilities
    )

    print(
        "[DASHBOARD] Highest CVSS:",
        highest_cvss
    )

    print(
        "[DASHBOARD] Incidents:",
        total_incidents
    )

    print(
        "[DASHBOARD] Remediations:",
        total_remediations
    )

    print(
        "[DASHBOARD] Open Remediations:",
        open_remediations
    )

    print(
        "[DASHBOARD] In Progress Remediations:",
        in_progress_remediations
    )

    print(
        "[DASHBOARD] Verified Remediations:",
        verified_remediations
    )

    print(
        "[DASHBOARD] Closed Remediations:",
        closed_remediations
    )

    print(
        "[DASHBOARD] Remediation Completion:",
        remediation_completion
    )

    print(
        "[DASHBOARD] Security Score:",
        security_score
    )


    # ======================================================
    # Render Dashboard
    # ======================================================

    return render_template(

        "dashboard.html",

        # --------------------------------------------------
        # Asset Statistics
        # --------------------------------------------------

        total_assets=total_assets,

        active_assets=active_assets,

        high_risk_assets=high_risk_assets,


        # --------------------------------------------------
        # Scan Statistics
        # --------------------------------------------------

        total_scans=total_scans,

        completed_scans=completed_scans,

        failed_scans=failed_scans,


        # --------------------------------------------------
        # Vulnerability Statistics
        # --------------------------------------------------

        total_vulnerabilities=total_vulnerabilities,

        unique_cve_count=unique_cve_count,

        critical_vulnerabilities=critical_vulnerabilities,

        high_vulnerabilities=high_vulnerabilities,

        medium_vulnerabilities=medium_vulnerabilities,

        low_vulnerabilities=low_vulnerabilities,

        highest_cvss=highest_cvss,


        # --------------------------------------------------
        # Incident Statistics
        # --------------------------------------------------

        total_incidents=total_incidents,

        open_incidents=open_incidents,

        critical_incidents=critical_incidents,


        # --------------------------------------------------
        # Remediation Statistics
        # --------------------------------------------------

        total_remediations=total_remediations,

        open_remediations=open_remediations,

        in_progress_remediations=in_progress_remediations,

        verified_remediations=verified_remediations,

        closed_remediations=closed_remediations,

        high_priority_remediations=high_priority_remediations,

        remediation_completion=remediation_completion,


        # --------------------------------------------------
        # Security Score
        # --------------------------------------------------

        security_score=security_score,


        # --------------------------------------------------
        # Recent Activity
        # --------------------------------------------------

        recent_scans=recent_scans,

        recent_incidents=recent_incidents,

        recent_audits=recent_audits

    )

# ==========================================================
# Create Database Tables
# ==========================================================

with app.app_context():

    db.create_all()


# ==========================================================
# Run Application
# ==========================================================

if __name__ == "__main__":

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=app.config["DEBUG"]

    )