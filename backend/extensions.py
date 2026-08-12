from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager


# ==========================================================
# Database
# ==========================================================

db = SQLAlchemy()


# ==========================================================
# Flask-Login
# ==========================================================

login_manager = LoginManager()


# ==========================================================
# Login Configuration
# ==========================================================

login_manager.login_view = "auth.login"

login_manager.login_message = "Please login first."

login_manager.login_message_category = "warning"