from flask_wtf import FlaskForm

from wtforms import StringField, SubmitField

from wtforms.validators import DataRequired, IPAddress


class ThreatForm(FlaskForm):

    ip = StringField(
        "IP Address",
        validators=[
            DataRequired(
                message="IP address is required."
            ),
            IPAddress(
                message="Please enter a valid IPv4 or IPv6 address."
            )
        ]
    )

    submit = SubmitField(
        "Analyze"
    )