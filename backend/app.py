from flask import Flask, render_template
from flask_login import login_required, current_user

from config import Config
from extensions import db, login_manager

from routes.auth import auth_bp
from routes.assets import assets_bp
from routes.scanner import scanner_bp
from routes.threat import threat_bp
from routes.incidents import incidents_bp
from routes.cve import cve_bp


from models.asset import Asset
from models.scan import Scan
from models.incident import Incident


# ==========================================
# Create Flask Application
# ==========================================
app = Flask(__name__)

# Load Configuration
app.config.from_object(Config)

# Initialize Extensions
db.init_app(app)
login_manager.init_app(app)

# Register Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(assets_bp)
app.register_blueprint(scanner_bp)
app.register_blueprint(threat_bp)
app.register_blueprint(incidents_bp)
app.register_blueprint(cve_bp)

# ==========================================
# Home Page
# ==========================================
@app.route("/")
def home():
    return render_template("index.html")


# ==========================================
# Dashboard
# ==========================================
@app.route("/dashboard")
@login_required
def dashboard():

    # ==============================
    # Asset Statistics
    # ==============================

    total_assets = Asset.query.count()

    active_assets = Asset.query.filter_by(
        status="Active"
    ).count()

    high_risk_assets = Asset.query.filter(
        Asset.risk_level.in_(["High", "Critical"])
    ).count()


    # ==============================
    # Scan Statistics
    # ==============================

    total_scans = Scan.query.count()

    completed_scans = Scan.query.filter_by(
        status="Completed"
    ).count()


    # ==============================
    # Incident Statistics
    # ==============================

    total_incidents = Incident.query.count()

    open_incidents = Incident.query.filter_by(
        status="Open"
    ).count()

    critical_incidents = Incident.query.filter(
        Incident.severity.in_(["Critical", "High"])
    ).filter(
        Incident.status != "Closed"
    ).count()


    # ==============================
    # Security Score
    # ==============================

    if total_assets > 0:
        asset_score = (
            (total_assets - high_risk_assets)
            / total_assets
        ) * 100
    else:
        asset_score = 100

    if total_incidents > 0:
        incident_score = (
            (total_incidents - critical_incidents)
            / total_incidents
        ) * 100
    else:
        incident_score = 100

    security_score = round(
        (asset_score + incident_score) / 2
    )


    # ==============================
    # Recent Scans
    # ==============================

    recent_scans = Scan.query.order_by(
        Scan.scan_date.desc()
    ).limit(5).all()


    # ==============================
    # Recent Incidents
    # ==============================

    recent_incidents = Incident.query.order_by(
        Incident.created_at.desc()
    ).limit(5).all()


    # ==============================
    # Dashboard
    # ==============================

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
        recent_incidents=recent_incidents
    )

# ==========================================
# Create Database Tables
# ==========================================
with app.app_context():
    db.create_all()


# ==========================================
# Run Application
# ==========================================
if __name__ == "__main__":
    app.run(debug=True)