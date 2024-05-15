from rest_framework.test import APITestCase
from rest_framework import serializers
from api.serializers import validate_procfile_type, BuildSerializer, ServiceSerializer


class ProcfileTypeTest(APITestCase):

    def assertException(self, method, exception=Exception, *args, **kwargs):
        try:
            method(*args, **kwargs)
        except BaseException as e:
            if not isinstance(e, exception):
                raise AssertionError(
                    "Did not throw the expected exception, "
                    f"actual: {type(e)}, expect: {exception}"
                )
        else:
            raise AssertionError(
                f"Did not throw the expected exception, args: {args}, kwargs: {kwargs}")

    def test_procfile_type_error(self):
        for procfile_type in ["w", "we", "-a", "we-canary", "w" * 64]:
            self.assertException(
                validate_procfile_type, serializers.ValidationError, procfile_type)

    def test_procfile_type_ok(self):
        self.assertEqual(validate_procfile_type("web"), "web")
        self.assertEqual(validate_procfile_type("w" * 63), "w" * 63)
        self.assertEqual(validate_procfile_type("web-canary-be"), "web-canary-be")

    def test_dryccfile_procfile_type(self):
        dryccfile_1 = {
            "build": {
                "docker": {
                    "web": "Dockerfile",
                    "task": "Dockerfile.task"
                },
            },
            "deploy": {
                "web": {
                    "args": ["python", "-m", "http.server", "5000"]
                },
                "task": {
                    "command": ["sleep"],
                    "args": ["infinity"]
                },
            }
        }
        validate_dryccfile = BuildSerializer().validate_dryccfile
        self.assertEqual(validate_dryccfile(dryccfile_1), dryccfile_1)
        dryccfile_1["build"]["docker"]["w"] = "Dockerfile.w"
        self.assertException(
                validate_dryccfile, serializers.ValidationError, dryccfile_1)
        del dryccfile_1["build"]["docker"]["w"]
        dryccfile_1["deploy"]["w"] = {"args": ["python", "-m", "http.server", "5000"]}
        self.assertException(
                validate_dryccfile, serializers.ValidationError, dryccfile_1)
        del dryccfile_1["deploy"]["w"]
        dryccfile_1["deploy"]["w-canary"] = {"args": ["python", "-m", "http.server", "5000"]}
        self.assertException(
                validate_dryccfile, serializers.ValidationError, dryccfile_1)

    def test_staticmethod_procfile_type(self):
        s_validate_procfile_type = ServiceSerializer().validate_procfile_type
        for procfile_type in ["w", "we", "-a", "we-canary", "w" * 64]:
            self.assertException(
                s_validate_procfile_type, serializers.ValidationError, procfile_type)
        self.assertEqual(s_validate_procfile_type("web"), "web")
        self.assertEqual(s_validate_procfile_type("w" * 63), "w" * 63)
        self.assertEqual(s_validate_procfile_type("web-canary-be"), "web-canary-be")
