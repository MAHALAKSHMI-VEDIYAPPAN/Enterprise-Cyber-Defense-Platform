import ipaddress

from flask_wtf import FlaskForm

from wtforms import (
    StringField,
    SelectField,
    SubmitField
)

from wtforms.validators import (
    DataRequired,
    ValidationError,
    Length
)


# ==========================================================
# IP Address Validator
# ==========================================================

def validate_ip_address(
    form,
    field
):

    value = field.data.strip()


    # ------------------------------------------------------
    # Validate IP Address
    # ------------------------------------------------------

    try:

        ipaddress.ip_address(
            value
        )

    except ValueError:

        raise ValidationError(
            "Please enter a valid IPv4 or IPv6 address."
        )


    # ------------------------------------------------------
    # Normalize Value
    # ------------------------------------------------------

    field.data = str(
        ipaddress.ip_address(
            value
        )
    )


# ==========================================================
# Asset Form
# ==========================================================

class AssetForm(FlaskForm):


    # ======================================================
    # Asset Name
    # ======================================================

    asset_name = StringField(

        "Asset Name",

        validators=[
            DataRequired(),
            Length(
                min=2,
                max=100
            )
        ]

    )


    # ======================================================
    # IP Address
    # ======================================================

    ip_address = StringField(

        "IP Address",

        validators=[
            DataRequired(),
            validate_ip_address
        ]

    )


    # ======================================================
    # Operating System
    # ======================================================

    operating_system = StringField(

        "Operating System",

        validators=[
            DataRequired(),
            Length(
                min=2,
                max=100
            )
        ]

    )


    # ======================================================
    # Owner
    # ======================================================

    owner = StringField(

        "Owner",

        validators=[
            DataRequired(),
            Length(
                min=2,
                max=100
            )
        ]

    )


    # ======================================================
    # Asset Type
    # ======================================================

    asset_type = SelectField(

        "Asset Type",

        choices=[

            (
                "Server",
                "Server"
            ),

            (
                "Laptop",
                "Laptop"
            ),

            (
                "Desktop",
                "Desktop"
            ),

            (
                "Router",
                "Router"
            ),

            (
                "Firewall",
                "Firewall"
            ),

            (
                "Switch",
                "Switch"
            )

        ]

    )


    # ======================================================
    # Risk Level
    # ======================================================

    risk_level = SelectField(

        "Risk Level",

        choices=[

            (
                "Low",
                "Low"
            ),

            (
                "Medium",
                "Medium"
            ),

            (
                "High",
                "High"
            ),

            (
                "Critical",
                "Critical"
            )

        ]

    )


    # ======================================================
    # Submit
    # ======================================================

    submit = SubmitField(
        "Add Asset"
    )