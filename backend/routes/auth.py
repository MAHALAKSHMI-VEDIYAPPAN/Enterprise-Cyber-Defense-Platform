from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash
)

from flask_login import (
    login_user,
    logout_user,
    login_required
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


    # ======================================================
    # Registration
    # ======================================================

    if form.validate_on_submit():

        # --------------------------------------------------
        # Normalize Input
        # --------------------------------------------------

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

        user.set_password(
            password
        )


        # --------------------------------------------------
        # Save User
        # --------------------------------------------------

        try:

            db.session.add(
                user
            )

            db.session.commit()


            # --------------------------------------------------
            # Audit Registration
            # --------------------------------------------------

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


    # ======================================================
    # Registration Page
    # ======================================================

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


    # ======================================================
    # Login
    # ======================================================

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

        if user and user.check_password(
            password
        ):

            # --------------------------------------------------
            # Reset Failed Attempts
            # --------------------------------------------------

            user.reset_login_attempts()


            # --------------------------------------------------
            # Create Login Session
            # --------------------------------------------------

            login_user(
                user
            )


            # --------------------------------------------------
            # Audit Successful Login
            # --------------------------------------------------

            log_action(
                "LOGIN_SUCCESS",
                "User logged in successfully."
            )


            # --------------------------------------------------
            # Success
            # --------------------------------------------------

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


            # --------------------------------------------------
            # Check Whether Account Was Locked
            # --------------------------------------------------

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


        # --------------------------------------------------
        # Generic Authentication Error
        # --------------------------------------------------

        flash(
            "Invalid Email or Password.",
            "danger"
        )


    # ======================================================
    # Login Page
    # ======================================================

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

    # ------------------------------------------------------
    # Audit Logout
    # ------------------------------------------------------

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