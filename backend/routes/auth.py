from flask import Blueprint, render_template, redirect, url_for, flash

from flask_login import login_user, logout_user, login_required

from forms.auth_forms import RegistrationForm, LoginForm
from models.user import User
from extensions import db

auth_bp = Blueprint("auth", __name__)


# -----------------------------
# Register
# -----------------------------
@auth_bp.route("/register", methods=["GET", "POST"])
def register():

    form = RegistrationForm()

    if form.validate_on_submit():

        existing_username = User.query.filter_by(
            username=form.username.data
        ).first()

        if existing_username:
            flash("Username already exists.")
            return redirect(url_for("auth.register"))

        existing_email = User.query.filter_by(
            email=form.email.data
        ).first()

        if existing_email:
            flash("Email already exists.")
            return redirect(url_for("auth.register"))

        user = User(
            username=form.username.data,
            email=form.email.data
        )

        user.set_password(form.password.data)

        db.session.add(user)
        db.session.commit()

        flash("Registration Successful!")

        return redirect(url_for("auth.login"))

    return render_template("register.html", form=form)


# -----------------------------
# Login
# -----------------------------
@auth_bp.route("/login", methods=["GET", "POST"])
def login():

    form = LoginForm()

    if form.validate_on_submit():

        user = User.query.filter_by(
            email=form.email.data
        ).first()

        if user and user.check_password(form.password.data):

            login_user(user)

            flash("Login Successful!")

            return redirect(url_for("dashboard"))

        flash("Invalid Email or Password")

    return render_template("login.html", form=form)


# -----------------------------
# Logout
# -----------------------------
@auth_bp.route("/logout")
@login_required
def logout():

    logout_user()

    flash("Logged out successfully.")

    return redirect(url_for("auth.login"))