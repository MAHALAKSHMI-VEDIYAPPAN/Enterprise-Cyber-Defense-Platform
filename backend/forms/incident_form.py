from flask_wtf import FlaskForm

from wtforms import (
    StringField,
    SelectField,
    TextAreaField,
    SubmitField
)

from wtforms.validators import (
    DataRequired,
    Length
)


class IncidentForm(FlaskForm):

    # ======================================================
    # Incident Title
    # ======================================================

    title = StringField(

        "Incident Title",

        validators=[
            DataRequired(
                message="Incident title is required."
            ),
            Length(
                min=3,
                max=200
            )
        ]

    )


    # ======================================================
    # Affected Asset
    # ======================================================

    asset = StringField(

        "Affected Asset",

        validators=[
            DataRequired(
                message="Affected asset is required."
            ),
            Length(
                min=1,
                max=100
            )
        ]

    )


    # ======================================================
    # Severity
    # ======================================================

    severity = SelectField(

        "Severity",

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

        ],

        default="Medium"

    )


    # ======================================================
    # Status
    # ======================================================

    status = SelectField(

        "Status",

        choices=[

            (
                "Open",
                "Open"
            ),

            (
                "In Progress",
                "In Progress"
            ),

            (
                "Resolved",
                "Resolved"
            ),

            (
                "Closed",
                "Closed"
            )

        ],

        default="Open"

    )


    # ======================================================
    # Assigned Analyst
    # ======================================================

    assigned_to = StringField(

        "Assigned Analyst",

        validators=[
            Length(
                max=100
            )
        ]

    )


    # ======================================================
    # Description
    # ======================================================

    description = TextAreaField(

        "Description",

        validators=[
            DataRequired(
                message="Incident description is required."
            )
        ]

    )


    # ======================================================
    # Resolution
    # ======================================================

    resolution = TextAreaField(

        "Resolution / Remediation",

        validators=[]

    )


    # ======================================================
    # Submit
    # ======================================================

    submit = SubmitField(
        "Create Incident"
    )