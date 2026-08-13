from flask_wtf import FlaskForm
from wtforms import (
    SelectField,
    StringField,
    SubmitField
)
from wtforms.validators import (
    DataRequired,
    IPAddress,
    Optional
)


# ==========================================================
# Vulnerability Scan Form
# ==========================================================

class ScanForm(FlaskForm):

    # ------------------------------------------------------
    # Asset Selection
    # ------------------------------------------------------

    asset_id = SelectField(
        "Select Asset",
        coerce=int,
        validators=[
            DataRequired(
                message="Please select an asset."
            )
        ]
    )

    # ------------------------------------------------------
    # Target IP
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