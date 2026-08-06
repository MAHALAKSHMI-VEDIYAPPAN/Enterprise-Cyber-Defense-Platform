from flask import Flask, render_template
from flask_login import login_required, current_user

from config import Config
from extensions import db, login_manager
from routes.auth import auth_bp
from models.asset import Asset
from routes.assets import assets_bp
from models.scan import Scan
from routes.scanner import scanner_bp

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

    return render_template(
        "dashboard.html",
        total_assets=total_assets
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