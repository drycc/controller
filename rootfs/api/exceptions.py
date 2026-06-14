from django.core.exceptions import ValidationError
from django.http import Http404
import logging
from rest_framework.exceptions import APIException, status
from rest_framework.response import Response
from rest_framework.views import set_rollback, exception_handler


def error_response(code: str, message: str, details=None, status_code: int = 400) -> Response:
    """
    Create a standardized error response.

    Format:
    {
        "error": {
            "code": "ERROR_CODE",
            "message": "Human readable message",
            "details": {}  // optional
        }
    }
    """
    error_body = {
        "error": {
            "code": code,
            "message": message,
        }
    }
    if details is not None:
        error_body["error"]["details"] = details
    return Response(error_body, status=status_code)


class HealthcheckException(APIException):
    """Exception class used for when the application's health check fails"""
    pass


class DryccException(APIException):
    status_code = 400


class AlreadyExists(APIException):
    status_code = 409


class Conflict(AlreadyExists):
    pass


class UnprocessableEntity(APIException):
    status_code = 422


class ServiceUnavailable(APIException):
    status_code = 503
    default_detail = 'Service temporarily unavailable, try again later.'


def custom_exception_handler(exc, context):
    # give more context on the error since DRF masks it as Not Found
    if isinstance(exc, Http404):
        set_rollback()
        return error_response('NOT_FOUND', str(exc), status_code=status.HTTP_404_NOT_FOUND)
    # Convert Django ValidationError to DRF 400 response
    if isinstance(exc, ValidationError):
        set_rollback()
        if hasattr(exc, 'message_dict'):
            return error_response(
                'VALIDATION_ERROR', 'Validation failed',
                exc.message_dict, status.HTTP_400_BAD_REQUEST)
        elif hasattr(exc, 'messages'):
            return error_response(
                'VALIDATION_ERROR', 'Validation failed',
                {'non_field_errors': exc.messages},
                status.HTTP_400_BAD_REQUEST)
        return error_response(
            'VALIDATION_ERROR', str(exc),
            status_code=status.HTTP_400_BAD_REQUEST)
    # Call REST framework's default exception handler after specific 404 handling,
    # to get the standard error response.
    response = exception_handler(exc, context)
    # No response means DRF couldn't handle it, output a generic 500 in a JSON format
    if response is None:
        logging.exception('Uncaught Exception', exc_info=exc)
        set_rollback()
        return error_response(
            'INTERNAL_ERROR', 'An internal error occurred',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
    # log a few different types of exception instead of using APIException
    if isinstance(exc, (DryccException, ServiceUnavailable, HealthcheckException)):
        logging.exception(str(exc), exc_info=True)
    return response
