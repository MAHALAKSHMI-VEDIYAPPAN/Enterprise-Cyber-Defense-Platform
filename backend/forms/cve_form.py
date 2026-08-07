from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired


class CVEForm(FlaskForm):

    keyword = StringField(
        "Software / Product",
        validators=[DataRequired()]
    )

    submit = SubmitField("Search CVEs")