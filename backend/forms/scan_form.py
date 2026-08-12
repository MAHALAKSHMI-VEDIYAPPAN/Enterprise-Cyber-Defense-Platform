from flask_wtf import FlaskForm

from wtforms import (
    StringField,
    SelectField,
    SubmitField
)

from wtforms.validators import (
    DataRequired,
    IPAddress
)


class ScanForm(FlaskForm):

    asset_id = SelectField(
        "Select Asset",
        coerce=int,
        validators=[
            DataRequired(
                message="Please select an asset."
            )
        ]
    )

    target = StringField(
        "Target IP Address",
        validators=[
            DataRequired(
                message="Please enter a target IP address."
            ),
            IPAddress(
                ipv4=True
            )
        ]
    )

    submit = SubmitField(
        "Start Scan"
    )