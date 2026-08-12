from flask_wtf import FlaskForm

from wtforms import StringField, SubmitField

from wtforms.validators import (
    DataRequired,
    Length
)


# ==========================================================
# CVE Search Form
# ==========================================================

class CVEForm(FlaskForm):

    # ======================================================
    # Software / Product Search
    # ======================================================

    keyword = StringField(
        "Software / Product",

        validators=[
            DataRequired(
                message="Please enter a software or product name."
            ),

            Length(
                min=2,
                max=100,
                message="Search must be between 2 and 100 characters."
            )
        ]
    )

    # ======================================================
    # Submit Button
    # ======================================================

    submit = SubmitField(
        "Search CVEs"
    )