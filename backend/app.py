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

    total_assets = Asset.query.count()

    total_scans = Scan.query.count()

    total_incidents = Incident.query.count()

    security_score = 92

    return render_template(
        "dashboard.html",
        total_assets=total_assets,
        total_scans=total_scans,
        total_incidents=total_incidents,
        security_score=security_score
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