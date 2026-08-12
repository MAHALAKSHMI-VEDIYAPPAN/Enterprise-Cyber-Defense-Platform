from datetime import datetime, timedelta

from flask_login import UserMixin

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from extensions import db, login_manager


# ==========================================================
# Login Security Configuration
# ==========================================================

MAX_LOGIN_ATTEMPTS = 5

LOCKOUT_MINUTES = 15


# ==========================================================
# User Model
# ==========================================================

class User(UserMixin, db.Model):

    __tablename__ = "users"


    # ======================================================
    # Primary Key
    # ======================================================

    id = db.Column(
        db.Integer,
        primary_key=True
    )


    # ======================================================
    # Username
    # ======================================================

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )


    # ======================================================
    # Email
    # ======================================================

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )


    # ======================================================
    # Password Hash
    # ======================================================

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )


    # ======================================================
    # User Role
    # ======================================================

    role = db.Column(
        db.String(20),
        nullable=False,
        default="Analyst"
    )


    # ======================================================
    # Failed Login Attempts
    # ======================================================

    failed_login_attempts = db.Column(
        db.Integer,
        nullable=False,
        default=0
    )


    # ======================================================
    # Account Lock Time
    # ======================================================

    locked_until = db.Column(
        db.DateTime,
        nullable=True
    )


    # ======================================================
    # Set Password
    # ======================================================

    def set_password(self, password):

        self.password_hash = generate_password_hash(
            password
        )


    # ======================================================
    # Check Password
    # ======================================================

    def check_password(self, password):

        return check_password_hash(
            self.password_hash,
            password
        )


    # ======================================================
    # Check Account Lock
    # ======================================================

    def is_locked(self):

        if not self.locked_until:

            return False


        # --------------------------------------------------
        # Lockout Expired
        # --------------------------------------------------

        if datetime.utcnow() >= self.locked_until:

            self.failed_login_attempts = 0

            self.locked_until = None

            db.session.commit()

            return False


        return True


    # ======================================================
    # Record Failed Login
    # ======================================================

    def record_failed_login(self):

        self.failed_login_attempts += 1


        # --------------------------------------------------
        # Lock Account
        # --------------------------------------------------

        if (
            self.failed_login_attempts
            >= MAX_LOGIN_ATTEMPTS
        ):

            self.locked_until = (
                datetime.utcnow()
                + timedelta(
                    minutes=LOCKOUT_MINUTES
                )
            )


        db.session.commit()


    # ======================================================
    # Reset Login Attempts
    # ======================================================

    def reset_login_attempts(self):

        self.failed_login_attempts = 0

        self.locked_until = None

        db.session.commit()


    # ======================================================
    # Representation
    # ======================================================

    def __repr__(self):

        return f"<User {self.username}>"


# ==========================================================
# Flask-Login User Loader
# ==========================================================

@login_manager.user_loader
def load_user(user_id):

    try:

        return db.session.get(
            User,
            int(user_id)
        )

    except (
        TypeError,
        ValueError
    ):

        return None