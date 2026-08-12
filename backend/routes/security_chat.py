from flask import (
    Blueprint,
    request,
    jsonify
)

from flask_login import (
    login_required,
    current_user
)

from services.security_chat_service import get_security_response


# ==========================================================
# Security Chat Blueprint
# ==========================================================

security_chat_bp = Blueprint(
    "security_chat",
    __name__
)


# ==========================================================
# Security Chat API
# ==========================================================

@security_chat_bp.route(
    "/api/security-chat",
    methods=["POST"]
)
@login_required
def security_chat():

    # ======================================================
    # RBAC
    # ======================================================

    if current_user.role not in [
        "Admin",
        "Analyst"
    ]:

        return jsonify({
            "success": False,
            "message": (
                "You do not have permission to use "
                "the Security Assistant."
            )
        }), 403


    # ======================================================
    # Validate JSON Request
    # ======================================================

    if not request.is_json:

        return jsonify({
            "success": False,
            "message": "Request must contain JSON data."
        }), 400


    data = request.get_json(
        silent=True
    )


    if not isinstance(data, dict):

        return jsonify({
            "success": False,
            "message": "Invalid JSON request."
        }), 400


    # ======================================================
    # Validate Question
    # ======================================================

    question = data.get(
        "question",
        ""
    )


    if not isinstance(question, str):

        return jsonify({
            "success": False,
            "message": "Security question must be text."
        }), 400


    question = question.strip()


    if not question:

        return jsonify({
            "success": False,
            "message": "Please enter a security question."
        }), 400


    # ======================================================
    # Maximum Question Length
    # ======================================================

    if len(question) > 500:

        return jsonify({
            "success": False,
            "message": (
                "Security questions must be "
                "500 characters or fewer."
            )
        }), 400


    # ======================================================
    # Generate Security Response
    # ======================================================

    response = get_security_response(
        question
    )


    # ======================================================
    # Return Response
    # ======================================================

    return jsonify({
        "success": True,
        "response": response
    })