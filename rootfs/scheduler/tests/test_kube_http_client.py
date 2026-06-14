"""
Unit tests for the Deis scheduler module.

Run the tests with "./manage.py test scheduler"
"""
import requests
import requests_mock
from unittest import mock
from packaging.version import parse

from django.test import TestCase

import scheduler


class KubeHTTPClientTest(TestCase):
    """Tests kubernetes HTTP client version calls"""

    def setUp(self):
        self.adapter = requests_mock.Adapter()
        self.url = 'http://versiontest.example.com'
        self.path = '/version'

        # Create a mock session that doesn't need k8s service account token
        mock_sess = requests.Session()

        # use the real scheduler client but with a mock session
        with mock.patch('scheduler._create_k8s_session', return_value=mock_sess):
            self.scheduler = scheduler.KubeHTTPClient(self.url)

        self.scheduler._session = mock_sess
        self.scheduler.session.mount(self.url, self.adapter)

    def test_version_for_gke(self):
        """
        Ensure that version() sanitizes info from GKE clusters
        """

        cases = {
                "1.12": {"major": "1", "minor": "12-gke"},
                "1.10": {"major": "1", "minor": "10-gke"},
                "1.9": {"major": "1", "minor": "9-gke"},
                "1.8": {"major": "1", "minor": "8-gke"},
                }

        for canonical in cases:
            resp = cases[canonical]
            self.adapter.register_uri('GET', self.url + self.path, json=resp)

            expected = parse(canonical)
            actual = self.scheduler.version()

            self.assertEqual(expected, actual, "{} breaks".format(resp))

    def test_version_for_eks(self):
        """
        Ensure that version() sanitizes info from EKS clusters
        """

        cases = {
                "1.12": {"major": "1", "minor": "12+"},
                "1.10": {"major": "1", "minor": "10+"},
                "1.9": {"major": "1", "minor": "9+"},
                "1.8": {"major": "1", "minor": "8+"},
                }

        for canonical in cases:
            resp = cases[canonical]
            self.adapter.register_uri('GET', self.url + self.path, json=resp)

            expected = parse(canonical)
            actual = self.scheduler.version()

            self.assertEqual(expected, actual, "{} breaks".format(resp))

    def test_version_vanilla(self):
        """
        Ensure that version() sanitizes info from vanilla k8s clusters
        """

        cases = {
                "1.12": {"major": "1", "minor": "12"},
                "1.10": {"major": "1", "minor": "10"},
                "1.9": {"major": "1", "minor": "9"},
                "1.8": {"major": "1", "minor": "8"},
                }

        for canonical in cases:
            resp = cases[canonical]
            self.adapter.register_uri('GET', self.url + self.path, json=resp)

            expected = parse(canonical)
            actual = self.scheduler.version()

            self.assertEqual(expected, actual, "{} breaks".format(resp))
