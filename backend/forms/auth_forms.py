from flask_wtf import FlaskForm

from wtforms import (
    StringField,
    PasswordField,
    SubmitField
)

from wtforms.validators import (
    DataRequired,
    Email,
    Length,
    Regexp
)


# ==========================================================
# Registration Form
# ==========================================================

class RegistrationForm(FlaskForm):

    username = StringField(
        "Username",
        validators=[
            DataRequired(
                message="Username is required."
            ),

            Length(
                min=3,
                max=30,
                message=(
                    "Username must be between "
                    "3 and 30 characters."
                )
            ),

            Regexp(
                r"^[A-Za-z0-9_.-]+$",
                message=(
                    "Username can contain only letters, "
                    "numbers, dots, underscores, and hyphens."
                )
            )
        ]
    )


    # ======================================================
    # Email
    # ======================================================

    email = StringField(
        "Email",
        validators=[
            DataRequired(
                message="Email is required."
            ),

            Email(
                message="Please enter a valid email address."
            ),

            Length(
                max=120,
                message=(
                    "Email must not exceed "
                    "120 characters."
                )
            )
        ]
    )


    # ======================================================
    # Password
    # ======================================================

    password = PasswordField(
        "Password",
        validators=[
            DataRequired(
                message="Password is required."
            ),

            Length(
                min=8,
                max=128,
                message=(
                    "Password must be between "
                    "8 and 128 characters."
                )
            ),

            Regexp(
                r"^(?=.*[A-Z])"
                r"(?=.*[a-z])"
                r"(?=.*\d)"
                r"(?=.*[^A-Za-z0-9]).+$",

                message=(
                    "Password must contain at least "
                    "one uppercase letter, one lowercase "
                    "letter, one number, and one special "
                    "character."
                )
            )
        ]
    )


    # ======================================================
    # Submit
    # ======================================================

    submit = SubmitField(
        "Create Account"
    )


# ==========================================================
# Login Form
# ==========================================================

class LoginForm(FlaskForm):

    email = StringField(
        "Email",
        validators=[
            DataRequired(
                message="Email is required."
            ),

            Email(
                message="Please enter a valid email address."
            ),

            Length(
                max=120,
                message=(
                    "Email must not exceed "
                    "120 characters."
                )
            )
        ]
    )


    # ======================================================
    # Password
    # ======================================================

    password = PasswordField(
        "Password",
        validators=[
            DataRequired(
                message="Password is required."
            ),

            Length(
                max=128,
                message=(
                    "Password must not exceed "
                    "128 characters."
                )
            )
        ]
    )


    # ======================================================
    # Submit
    # ======================================================

    submit = SubmitField(
        "Login"
    )