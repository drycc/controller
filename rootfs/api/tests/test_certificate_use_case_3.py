from django.contrib.auth import get_user_model
from django.core.cache import cache

from api.models.app import App
from api.models.base import PROCFILE_TYPE_WEB
from api.models.certificate import Certificate
from api.models.domain import Domain
from api.tests import TEST_ROOT, DryccTestCase

User = get_user_model()


class CertificateUseCase3Test(DryccTestCase):

    """
    Tests creation of 2 domains and 2 SSL certificate.
    Attach each certificate to a matching domain and then detach.
    """

    fixtures = ['tests.json']

    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)

        self.app = App.objects.create(owner=self.user, id='test-app-use-case-3')
        self.url = f'/v2/apps/{self.app.id}/certs'
        self.domains = {
            'foo.com': Domain.objects.create(
                owner=self.user, app=self.app, domain='foo.com', procfile_type=PROCFILE_TYPE_WEB),
            'bar.com': Domain.objects.create(
                owner=self.user, app=self.app, domain='bar.com', procfile_type=PROCFILE_TYPE_WEB),
        }

        self.certificates = {}

        # load up the certs
        for domain in self.domains:
            self.certificates[domain] = {'name': domain.replace('.', '-')}
            with open('{}/certs/{}.key'.format(TEST_ROOT, domain)) as f:
                self.certificates[domain]['key'] = f.read()

            with open('{}/certs/{}.cert'.format(TEST_ROOT, domain)) as f:
                self.certificates[domain]['cert'] = f.read()

        # add expires and fingerprints
        self.certificates['foo.com']['expires'] = '2017-01-14T23:55:59Z'
        self.certificates['foo.com']['fingerprint'] = 'AC:82:58:80:EA:C4:B9:75:C1:1C:52:48:40:28:15:1D:47:AC:ED:88:4B:D4:72:95:B2:C0:A0:DF:4A:A7:60:B6'  # noqa

        self.certificates['bar.com']['expires'] = '2017-01-14T23:57:57Z'
        self.certificates['bar.com']['fingerprint'] = '7A:CA:B8:50:FF:8D:EB:03:3D:AC:AD:13:4F:EE:03:D5:5D:EB:5E:37:51:8C:E0:98:F8:1B:36:2B:20:83:0D:C0'  # noqa

    def tearDown(self):
        # make sure every test has a clean slate for k8s mocking
        cache.clear()

    def test_create_certificate_with_domain(self):
        """Tests creating a certificate."""
        for domain, certificate in self.certificates.items():
            response = self.client.post(
                self.url,
                {
                    'name': certificate['name'],
                    'certificate': certificate['cert'],
                    'key': certificate['key']
                }
            )
            self.assertEqual(response.status_code, 201, response.data)

    def test_get_certificate_screens_data(self):
        """
        When a user retrieves a certificate, only the common name and expiry date should be
        displayed.
        """
        for domain, certificate in self.certificates.items():
            # Create certificate
            response = self.client.post(
                self.url,
                {
                    'name': certificate['name'],
                    'certificate': certificate['cert'],
                    'key': certificate['key']
                }
            )
            self.assertEqual(response.status_code, 201, response.data)

            # Attach domain to certificate
            response = self.client.post(
                '{}/{}/domain/'.format(self.url, certificate['name']),
                {'domain': domain}
            )
            self.assertEqual(response.status_code, 201, response.data)

            # Assert data
            response = self.client.get('{}/{}'.format(self.url, certificate['name']))
            self.assertEqual(response.status_code, 200, response.data)

            expected = {
                'name': certificate['name'],
                'common_name': str(domain),
                'expires': certificate['expires'],
                'fingerprint': certificate['fingerprint'],
                'san': [],
                'domains': [domain]
            }
            for key, value in list(expected.items()):
                self.assertEqual(
                    response.data[key],
                    value,
                    '{} - {}'.format(certificate['name'], key)
                )

            # detach certificate from domain
            response = self.client.delete(
                '{}/{}/domain/{}'.format(self.url, certificate['name'], domain)
            )
            self.assertEqual(response.status_code, 204, response.data)

            # Assert data
            response = self.client.get('{}/{}'.format(self.url, certificate['name']))
            self.assertEqual(response.status_code, 200, response.data)
            self.assertEqual(response.data['domains'], [])

    def test_certficate_denied_requests(self):
        """Disallow put/patch requests"""
        response = self.client.put(self.url)
        self.assertEqual(response.status_code, 405, response.content)
        response = self.client.patch(self.url)
        self.assertEqual(response.status_code, 405, response.content)

    def test_delete_certificate(self):
        """Destroying a certificate should generate a 204 response"""
        for domain, certificate in self.certificates.items():
            Certificate.objects.create(
                name=certificate['name'],
                app=self.app,
                owner=self.user,
                common_name=domain,
                certificate=certificate['cert'],
                key=certificate['key']
            )
            url = f'/v2/apps/{self.app.id}/certs/{certificate['name']}/'
            response = self.client.delete(url)
            self.assertEqual(response.status_code, 204, response.data)
