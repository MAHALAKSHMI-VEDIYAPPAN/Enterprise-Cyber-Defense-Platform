from flask import (
    Blueprint,
    render_template,
    request,
    jsonify
)

from flask_login import login_required

from services.ai_security_service import (
    generate_security_analysis,
    ask_security_ai
)


# ==========================================================
# Blueprint
# ==========================================================

ai_security_bp = Blueprint(
    "ai_security",
    __name__
)


# ==========================================================
# AI Assistant Page
# ==========================================================

@ai_security_bp.route(
    "/ai-assistant",
    methods=["GET", "POST"]
)
@login_required
def ai_assistant():

    # ======================================================
    # Generate Current ECDP Analysis
    # ======================================================

    try:

        analysis = generate_security_analysis()

    except Exception as error:

        print(
            "[AI SECURITY] Analysis error:",
            str(error)
        )

        analysis = {
            "score": 0,

            "risk_level": "Unknown",

            "summary": (
                "Security analysis is currently unavailable."
            ),

            "statistics": {
                "total_assets": 0,
                "active_assets": 0,
                "high_risk_assets": 0,

                "total_scans": 0,
                "completed_scans": 0,
                "failed_scans": 0,

                "total_incidents": 0,
                "open_incidents": 0,

                "critical_incidents": 0,
                "high_incidents": 0,
                "medium_incidents": 0,
                "low_incidents": 0,

                "total_remediations": 0,
                "open_remediations": 0,
                "in_progress_remediations": 0,
                "resolved_remediations": 0,
                "verified_remediations": 0
            },

            "recommendations": []
        }


    # ======================================================
    # POST Request - AI Question
    # ======================================================

    if request.method == "POST":

        # --------------------------------------------------
        # Get Question
        # --------------------------------------------------

        question = (
            request.form.get("question")
            or request.form.get("message")
            or ""
        ).strip()


        # --------------------------------------------------
        # Empty Question
        # --------------------------------------------------

        if not question:

            answer = (
                "Please enter a cybersecurity question."
            )

        else:

            # ------------------------------------------------
            # Ask General-Purpose Security AI
            # ------------------------------------------------

            answer = ask_security_ai(
                question
            )


        # ==================================================
        # JSON Request
        # ==================================================

        wants_json = (

            request.is_json

            or

            request.headers.get(
                "X-Requested-With"
            ) == "XMLHttpRequest"

            or

            "application/json"
            in request.headers.get(
                "Accept",
                ""
            )
        )


        if wants_json:

            return jsonify({

                "success": True,

                "question": question,

                "answer": answer

            })


        # ==================================================
        # Normal Form Submission
        # ==================================================

        return render_template(

            "ai_security.html",

            analysis=analysis,

            question=question,

            answer=answer

        )


    # ======================================================
    # GET Request
    # ======================================================

    return render_template(

        "ai_security.html",

        analysis=analysis,

        question="",

        answer=""

    )