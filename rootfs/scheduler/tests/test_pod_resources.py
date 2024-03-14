import unittest
from scheduler.resources.pod import Pod


class TestSchedulerPodResources(unittest.TestCase):
    def test_manifest_limits(self):
        resources_cases = [
            {"app_type": "web", "expected": {"limits": {"cpu": 1}}},
            {"app_type": "web", "expected": {"limits": {"memory": "1G"}}},
            {"app_type": "web", "expected": {"limits": {"cpu": 1, "memory": "1G"}}},
        ]
        for caze in resources_cases:
            manifest = Pod("").manifest("",
                                        "",
                                        "",
                                        app_type=caze["app_type"],
                                        resources=caze["expected"])
            self._assert_resources(caze, manifest)

    def _assert_resources(self, caze, manifest):
        resources_parent = manifest["spec"]["containers"][0]
        expected = caze["expected"]
        if expected:
            self.assertEqual(resources_parent["resources"], expected, caze)
        else:
            self.assertTrue(resources_parent["resources"] == {}, caze)
