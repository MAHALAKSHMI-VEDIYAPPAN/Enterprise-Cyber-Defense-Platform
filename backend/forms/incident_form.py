from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    SelectField,
    TextAreaField,
    SubmitField
)
from wtforms.validators import DataRequired


class IncidentForm(FlaskForm):

    title = StringField(
        "Incident Title",
        validators=[DataRequired()]
    )

    asset = StringField(
        "Affected Asset",
        validators=[DataRequired()]
    )

    severity = SelectField(
        "Severity",
        choices=[
            ("Low", "Low"),
            ("Medium", "Medium"),
            ("High", "High"),
            ("Critical", "Critical")
        ]
    )

    assigned_to = StringField("Assigned Analyst")

    description = TextAreaField(
        "Description",
        validators=[DataRequired()]
    )

    submit = SubmitField("Create Incident")