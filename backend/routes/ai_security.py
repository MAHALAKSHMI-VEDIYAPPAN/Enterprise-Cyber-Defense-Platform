from flask import (
    Blueprint,
    render_template,
    flash
)

from flask_login import (
    login_required,
    current_user
)

from services.ai_security_service import generate_security_analysis


# ==========================================================
# AI Security Assistant Blueprint
# ==========================================================

ai_security_bp = Blueprint(
    "ai_security",
    __name__
)


# ==========================================================
# AI Security Assistant
# ==========================================================

@ai_security_bp.route("/ai-assistant")
@login_required
def ai_assistant():

    # ======================================================
    # Role Check
    # ======================================================

    if current_user.role not in [
        "Admin",
        "Analyst"
    ]:

        flash(
            "You do not have permission to generate "
            "security analysis.",
            "danger"
        )

        return render_template(
            "ai_security.html",
            analysis=None
        )


    # ======================================================
    # Generate Security Analysis
    # ======================================================

    analysis = generate_security_analysis()


    # ======================================================
    # Render AI Security Page
    # ======================================================

    return render_template(
        "ai_security.html",
        analysis=analysis
    )