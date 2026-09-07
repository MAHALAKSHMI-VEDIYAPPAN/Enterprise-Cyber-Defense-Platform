from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request
)

from flask_login import (
    login_user,
    logout_user,
    login_required,
    current_user
)

from sqlalchemy.exc import IntegrityError

from forms.auth_forms import (
    RegistrationForm,
    LoginForm
)

from models.user import User

from extensions import db

from utils.audit_logger import log_action


# ==========================================================
# Authentication Blueprint
# ==========================================================

auth_bp = Blueprint(
    "auth",
    __name__
)


# ==========================================================
# Register
# ==========================================================

@auth_bp.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    form = RegistrationForm()

    if form.validate_on_submit():

        username = form.username.data.strip()

        email = form.email.data.strip().lower()

        password = form.password.data

        # --------------------------------------------------
        # Check Existing Username
        # --------------------------------------------------

        existing_username = User.query.filter_by(
            username=username
        ).first()

        if existing_username:

            flash(
                "Username already exists.",
                "warning"
            )

            return redirect(
                url_for("auth.register")
            )

        # --------------------------------------------------
        # Check Existing Email
        # --------------------------------------------------

        existing_email = User.query.filter_by(
            email=email
        ).first()

        if existing_email:

            flash(
                "Email already exists.",
                "warning"
            )

            return redirect(
                url_for("auth.register")
            )

        # --------------------------------------------------
        # Create User
        # --------------------------------------------------

        user = User(
            username=username,
            email=email,
            role="Analyst"
        )

        # --------------------------------------------------
        # Secure Password Hashing
        # --------------------------------------------------

        user.set_password(password)

        # --------------------------------------------------
        # Save User
        # --------------------------------------------------

        try:

            db.session.add(user)

            db.session.commit()

            log_action(
                "USER_REGISTERED",
                f"New user account registered: {username}"
            )

        except IntegrityError:

            db.session.rollback()

            flash(
                "Unable to create the account. "
                "The username or email may already exist.",
                "danger"
            )

            return redirect(
                url_for("auth.register")
            )

        # --------------------------------------------------
        # Success
        # --------------------------------------------------

        flash(
            "Registration successful!",
            "success"
        )

        return redirect(
            url_for("auth.login")
        )

    return render_template(
        "register.html",
        form=form
    )


# ==========================================================
# Login
# ==========================================================

@auth_bp.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    form = LoginForm()

    if form.validate_on_submit():

        email = form.email.data.strip().lower()

        password = form.password.data

        # --------------------------------------------------
        # Find User
        # --------------------------------------------------

        user = User.query.filter_by(
            email=email
        ).first()

        # ==================================================
        # Account Lock Check
        # ==================================================

        if user and user.is_locked():

            log_action(
                "LOGIN_BLOCKED",
                "Login attempt blocked because "
                "the account is locked."
            )

            flash(
                "Unable to login. Please try again later.",
                "danger"
            )

            return render_template(
                "login.html",
                form=form
            )

        # ==================================================
        # Verify Credentials
        # ==================================================

        if user and user.check_password(password):

            user.reset_login_attempts()

            login_user(user)

            log_action(
                "LOGIN_SUCCESS",
                "User logged in successfully."
            )

            flash(
                "Login successful!",
                "success"
            )

            return redirect(
                url_for("dashboard")
            )

        # ==================================================
        # Failed Login
        # ==================================================

        if user:

            user.record_failed_login()

            if user.is_locked():

                log_action(
                    "ACCOUNT_LOCKED",
                    "Account temporarily locked after "
                    "multiple failed login attempts."
                )

            else:

                log_action(
                    "LOGIN_FAILED",
                    "Invalid password."
                )

        else:

            log_action(
                "LOGIN_FAILED",
                "Login attempt for an unknown account."
            )

        flash(
            "Invalid Email or Password.",
            "danger"
        )

    return render_template(
        "login.html",
        form=form
    )


# ==========================================================
# Logout
# ==========================================================

@auth_bp.route(
    "/logout"
)
@login_required
def logout():

    log_action(
        "LOGOUT",
        "User logged out successfully."
    )

    logout_user()

    flash(
        "Logged out successfully.",
        "success"
    )

    return redirect(
        url_for("auth.login")
    )


# ==========================================================
# Settings
# ==========================================================

@auth_bp.route(
    "/settings",
    methods=["GET", "POST"]
)
@login_required
def settings():

    # ------------------------------------------------------
    # Update Profile
    # ------------------------------------------------------

    if request.method == "POST":

        action = request.form.get("action")

        # ==================================================
        # Profile Update
        # ==================================================

        if action == "update_profile":

            username = (
                request.form.get("username", "")
                .strip()
            )

            email = (
                request.form.get("email", "")
                .strip()
                .lower()
            )

            if not username or not email:

                flash(
                    "Username and email are required.",
                    "warning"
                )

                return redirect(
                    url_for("auth.settings")
                )

            # --------------------------------------------------
            # Check Username Conflict
            # --------------------------------------------------

            username_exists = User.query.filter(
                User.username == username,
                User.id != current_user.id
            ).first()

            if username_exists:

                flash(
                    "That username is already in use.",
                    "danger"
                )

                return redirect(
                    url_for("auth.settings")
                )

            # --------------------------------------------------
            # Check Email Conflict
            # --------------------------------------------------

            email_exists = User.query.filter(
                User.email == email,
                User.id != current_user.id
            ).first()

            if email_exists:

                flash(
                    "That email address is already in use.",
                    "danger"
                )

                return redirect(
                    url_for("auth.settings")
                )

            # --------------------------------------------------
            # Update User
            # --------------------------------------------------

            current_user.username = username

            current_user.email = email

            try:

                db.session.commit()

                log_action(
                    "PROFILE_UPDATED",
                    "User profile information was updated."
                )

                flash(
                    "Profile updated successfully.",
                    "success"
                )

            except IntegrityError:

                db.session.rollback()

                flash(
                    "Unable to update profile.",
                    "danger"
                )

            return redirect(
                url_for("auth.settings")
            )

        # ==================================================
        # Password Update
        # ==================================================

        elif action == "change_password":

            current_password = request.form.get(
                "current_password",
                ""
            )

            new_password = request.form.get(
                "new_password",
                ""
            )

            confirm_password = request.form.get(
                "confirm_password",
                ""
            )

            # --------------------------------------------------
            # Validate Current Password
            # --------------------------------------------------

            if not current_user.check_password(
                current_password
            ):

                log_action(
                    "PASSWORD_CHANGE_FAILED",
                    "Password change failed because "
                    "the current password was incorrect."
                )

                flash(
                    "Current password is incorrect.",
                    "danger"
                )

                return redirect(
                    url_for("auth.settings")
                )

            # --------------------------------------------------
            # Password Length
            # --------------------------------------------------

            if len(new_password) < 8:

                flash(
                    "New password must contain at least 8 characters.",
                    "warning"
                )

                return redirect(
                    url_for("auth.settings")
                )

            # --------------------------------------------------
            # Confirm Password
            # --------------------------------------------------

            if new_password != confirm_password:

                flash(
                    "New passwords do not match.",
                    "warning"
                )

                return redirect(
                    url_for("auth.settings")
                )

            # --------------------------------------------------
            # Prevent Same Password
            # --------------------------------------------------

            if current_user.check_password(
                new_password
            ):

                flash(
                    "New password must be different "
                    "from the current password.",
                    "warning"
                )

                return redirect(
                    url_for("auth.settings")
                )

            # --------------------------------------------------
            # Update Password
            # --------------------------------------------------

            current_user.set_password(
                new_password
            )

            db.session.commit()

            log_action(
                "PASSWORD_CHANGED",
                "User password was changed successfully."
            )

            flash(
                "Password changed successfully.",
                "success"
            )

            return redirect(
                url_for("auth.settings")
            )

    # ------------------------------------------------------
    # Settings Page
    # ------------------------------------------------------

    return render_template(
        "settings.html",
        user=current_user
    )