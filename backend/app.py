import os

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

# Audit Logs Blueprint
from routes.audit import audit_bp


# ==========================================================
# Models
# ==========================================================

from models.asset import Asset
from models.scan import Scan
from models.incident import Incident
from models.audit_log import AuditLog


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
    # Render Dashboard
    # ======================================================

    return render_template(

        "dashboard.html",

        total_assets=total_assets,

        active_assets=active_assets,

        high_risk_assets=high_risk_assets,

        total_scans=total_scans,

        completed_scans=completed_scans,

        total_incidents=total_incidents,

        open_incidents=open_incidents,

        critical_incidents=critical_incidents,

        security_score=security_score,

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