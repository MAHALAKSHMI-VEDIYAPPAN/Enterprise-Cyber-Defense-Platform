from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, IPAddress


class ScanForm(FlaskForm):

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

    submit = SubmitField("Start Scan")