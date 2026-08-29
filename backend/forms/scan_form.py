from flask_wtf import FlaskForm

from wtforms import (
    SelectField,
    StringField,
    SubmitField
)

from wtforms.validators import (
    IPAddress,
    DataRequired,
    Optional
)


# ==========================================================
# Vulnerability Scan Form
# ==========================================================

class ScanForm(FlaskForm):

    # ------------------------------------------------------
    # Asset Selection
    # ------------------------------------------------------
    #
    # Asset selection is OPTIONAL.
    #
    # This allows the user to:
    #
    # 1. Scan an existing registered asset
    #
    # OR
    #
    # 2. Enter a new authorized target IP directly.
    #
    # ------------------------------------------------------

    asset_id = SelectField(
        "Select Asset",
        coerce=int,
        validators=[
            Optional()
        ]
    )


    # ------------------------------------------------------
    # Target IP
    # ------------------------------------------------------
    #
    # Target IP is always required.
    #
    # If an existing asset is selected, the IP is
    # automatically populated from the asset.
    #
    # If no asset is selected, the user can enter
    # the authorized target IP manually.
    #
    # ------------------------------------------------------

    target = StringField(
        "Target IP Address",
        validators=[
            DataRequired(
                message="Target IP address is required."
            ),

            IPAddress(
                message="Enter a valid IP address."
            )
        ]
    )


    # ------------------------------------------------------
    # Submit
    # ------------------------------------------------------

    submit = SubmitField(
        "Start Scan"
    )