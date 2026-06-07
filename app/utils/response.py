"""Standard JSON response helpers for API routes."""

from datetime import datetime

from flask import jsonify


def _timestamp():
    return datetime.utcnow().isoformat() + "Z"


def success_response(data=None, message="Success", status_code=200):
    response = jsonify(
        {
            "status": "success",
            "message": message,
            "data": data,
            "timestamp": _timestamp(),
        }
    )
    response.status_code = status_code
    return response


def error_response(message="Error", status_code=400, errors=None):
    response = jsonify(
        {
            "status": "error",
            "message": message,
            "errors": errors or {},
            "timestamp": _timestamp(),
        }
    )
    response.status_code = status_code
    return response


def validation_error_response(errors_dict):
    return error_response(
        message="Validation failed",
        status_code=422,
        errors=errors_dict,
    )


def not_found_response(resource="Resource"):
    return error_response(message=f"{resource} not found", status_code=404)


def unauthorized_response():
    return error_response(message="Authentication required", status_code=401)
