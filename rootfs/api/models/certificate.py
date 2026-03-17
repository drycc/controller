import logging

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtensionOID, NameOID
from pytz import utc

from django.shortcuts import get_object_or_404
from django.db import models
from django.core.exceptions import SuspiciousOperation
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from api.utils import validate_label
from api.exceptions import ServiceUnavailable
from scheduler import KubeException
from .base import AuditedModel
from .domain import Domain

User = get_user_model()
logger = logging.getLogger(__name__)


def get_subj_alt_name(peer_cert):
    try:
        san_extension = peer_cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound:
        return []

    return san_extension.value.get_values_for_type(x509.DNSName)


def public_keys_match(cert_public_key, private_key):
    def _public_key_der(key):
        """Serialize any public key to DER SubjectPublicKeyInfo bytes."""
        return key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    return _public_key_der(cert_public_key) == _public_key_der(
        private_key.public_key()
    )


def get_certificate_not_valid_after(certificate):
    if hasattr(certificate, 'not_valid_after_utc'):
        return certificate.not_valid_after_utc

    return certificate.not_valid_after.replace(tzinfo=utc)


def get_certificate_not_valid_before(certificate):
    if hasattr(certificate, 'not_valid_before_utc'):
        return certificate.not_valid_before_utc

    return certificate.not_valid_before.replace(tzinfo=utc)


def validate_certificate(value):
    try:
        certificate_bytes = value.encode('utf-8') if isinstance(value, str) else value
        return x509.load_pem_x509_certificate(certificate_bytes)
    except (TypeError, ValueError) as e:
        raise ValidationError('Could not load certificate: {}'.format(e))


def validate_private_key(value):
    try:
        private_key_bytes = value.encode('utf-8') if isinstance(value, str) else value
        return serialization.load_pem_private_key(private_key_bytes, password=None)
    except (TypeError, ValueError) as e:
        raise ValidationError('Could not load private key: {}'.format(e))


def validate_cert_pair(certificate, private_key):
    # Load and validate the certificate and private key
    try:
        cert = validate_certificate(certificate)
        pkey = validate_private_key(private_key)
    except ValidationError as e:
        # The certificate and key should already have been validated
        raise SuspiciousOperation(e)

    if not public_keys_match(cert.public_key(), pkey):
        raise ValidationError('Certificate and private key do not match!')

    # Return tuple if everything went ok
    return (cert, pkey)


class Certificate(AuditedModel):
    """
    Public and private key pair used to secure application traffic at the router.
    """
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    name = models.CharField(max_length=253, validators=[validate_label])
    # there is no upper limit on the size of an x.509 certificate
    certificate = models.TextField(validators=[validate_certificate])
    key = models.TextField(validators=[validate_private_key])
    # X.509 certificates allow any string of information as the common name.
    common_name = models.TextField(editable=False, unique=False, null=True)
    # A list of DNS records if certificate has SubjectAltName
    san = models.JSONField(default=None, null=True)
    # SHA256 fingerprint
    fingerprint = models.CharField(max_length=96, editable=False)
    # Expires and Start time of cert
    expires = models.DateTimeField(editable=False)
    starts = models.DateTimeField(editable=False)
    issuer = models.TextField(editable=False)
    subject = models.TextField(editable=False)

    class Meta:
        ordering = ['name', 'common_name', 'expires']
        unique_together = ('app', 'name')

    @property
    def domains(self):
        domains = []
        for data in Domain.objects.filter(certificate=self).distinct().order_by('domain'):
            domains.append(data.domain)

        return domains

    @property
    def certname(self):
        return '%s-certificate' % self.name

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        # Validate the provided certificate and key pair and test for a mismatch
        certificate, _ = validate_cert_pair(self.certificate, self.key)

        if not self.common_name:
            common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            self.common_name = common_names[0].value if common_names else None

        # Grab expire date of the certificate
        if not self.expires:
            self.expires = get_certificate_not_valid_after(certificate)

        # Grab the start date of the certificate
        if not self.starts:
            self.starts = get_certificate_not_valid_before(certificate)

        # process issuers - separate each key/value with a slash
        self.issuer = certificate.issuer.rfc4514_string()

        # process subject - separate each key/value with a slash
        self.subject = certificate.subject.rfc4514_string()

        # public fingerprint of certificate
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex().upper()
        self.fingerprint = ':'.join(fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2))

        # SubjectAltName from the certificate - return a list
        self.san = get_subj_alt_name(certificate)

        return super(Certificate, self).save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        # Remove from k8s and domain object if there are any
        if self.domains:
            for domain in self.domains:
                kwargs['domain'] = domain
                self.detach(*args, **kwargs)
                del kwargs['domain']

        # Delete from DB
        return super(Certificate, self).delete(*args, **kwargs)

    def attach(self, *args, **kwargs):
        # add the certificate to the domain
        domain = get_object_or_404(Domain, domain=kwargs['domain'])
        # create in kubernetes
        self.attach_in_kubernetes(domain)
        domain.certificate = self
        domain.save()

    def attach_in_kubernetes(self, domain):
        """Creates the certificate as a kubernetes secret"""
        # only create if it exists - We raise an exception when a secret doesn't exist
        try:
            namespace = domain.app.id
            data = {
                'tls.crt': self.certificate,
                'tls.key': self.key
            }

            secret = self.scheduler.secret.get(namespace, self.certname).json()['data']
        except KubeException:
            self.scheduler.secret.create(namespace, self.certname, data)
        else:
            # update cert secret to the TLS Ingress format if required
            if secret != data:
                try:
                    self.scheduler.secret.update(namespace, self.certname, data)
                except KubeException as e:
                    msg = 'There was a problem updating the certificate secret ' \
                          '{} for {}'.format(self.certname, namespace)
                    raise ServiceUnavailable(msg) from e

    def detach(self, *args, **kwargs):
        # remove the certificate from the domain
        domain = get_object_or_404(Domain, domain=kwargs['domain'])
        domain.certificate = None
        domain.save()

        namespace = domain.app.id

        # only delete if it exists and if no other domains depend on secret
        if len(self.domains) == 0:
            try:
                # We raise an exception when a secret doesn't exist
                self.scheduler.secret.get(namespace, self.certname)
                self.scheduler.secret.delete(namespace, self.certname)
            except KubeException as e:
                raise ServiceUnavailable(
                    "Could not delete certificate secret {} for application {}".format(
                        self.certname, namespace)) from e
