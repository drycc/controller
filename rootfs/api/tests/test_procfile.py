from rest_framework.test import APITestCase
from rest_framework import serializers
from api.serializers import validate_ptype, BuildSerializer, ServiceSerializer


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

    def test_ptype_error(self):
        for ptype in ["w", "we", "-a", "we-new-", "w" * 64]:
            self.assertException(
                validate_ptype, serializers.ValidationError, ptype)

    def test_ptype_ok(self):
        self.assertEqual(validate_ptype("web"), "web")
        self.assertEqual(validate_ptype("w" * 63), "w" * 63)
        self.assertEqual(validate_ptype("web-new-be"), "web-new-be")

    def test_dryccfile_ptype(self):
        dryccfile_1 = {
            "pipeline": {
                "web.yaml": {
                    "kind": "pipeline",
                    "ptype": "web",
                    "build": {
                        "docker": "Dockerfile",
                    },
                    "deploy": {
                        "args": ["python", "-m", "http.server", "5000"],
                    },
                },
                "worker.yaml": {
                    "kind": "pipeline",
                    "ptype": "worker",
                    "build": {
                        "docker": "Dockerfile.task",
                    },
                    "deploy": {
                        "command": ["sleep"],
                        "args": ["infinity"]
                    },
                }
            }
        }
        validate_dryccfile = BuildSerializer().validate_dryccfile
        self.assertEqual(validate_dryccfile(dryccfile_1), dryccfile_1)
        dryccfile_1["pipeline"]["w.yaml"] = {
            "kind": "pipeline",
            "ptype": "w",
            "build": {"docker": "Dockerfile.task"},
        }
        self.assertException(
                validate_dryccfile, serializers.ValidationError, dryccfile_1)
        del dryccfile_1["pipeline"]["w.yaml"]

        dryccfile_1["pipeline"]["w.yaml"] = {
            "kind": "pipeline",
            "ptype": "w",
            "build": {"docker": "Dockerfile.task"},
            "deploy": {"args": ["python", "-m", "http.server", "5000"]},
        }
        self.assertException(
                validate_dryccfile, serializers.ValidationError, dryccfile_1)
        dryccfile_1["pipeline"]["w.yaml"]

        dryccfile_1["pipeline"]["wnew.yaml"] = {
            "kind": "pipeline",
            "ptype": "w-new-",
            "build": {"docker": "Dockerfile.task"},
            "deploy": {"args": ["python", "-m", "http.server", "5000"]},
        }
        self.assertException(
                validate_dryccfile, serializers.ValidationError, dryccfile_1)

    def test_staticmethod_ptype(self):
        s_validate_ptype = ServiceSerializer().validate_ptype
        for ptype in ["w", "we", "-a", "we-new-", "w" * 64]:
            self.assertException(
                s_validate_ptype, serializers.ValidationError, ptype)
        self.assertEqual(s_validate_ptype("web"), "web")
        self.assertEqual(s_validate_ptype("w" * 63), "w" * 63)
        self.assertEqual(s_validate_ptype("web-new-be"), "web-new-be")
