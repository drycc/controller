import logging
import string
import copy
import json
import uuid
import hashlib
from django.db import models, transaction
from django.conf import settings
from django.contrib.auth import get_user_model
from api.utils import unit_to_bytes, validate_label
from api.exceptions import DryccException, ServiceUnavailable
from scheduler import KubeException
from .base import UuidAuditedModel

User = get_user_model()
logger = logging.getLogger(__name__)


class Volume(UuidAuditedModel):
    TYPE_CHOICES = (
        ("csi", "container storage interface"),
        ("nfs", "network file system"),
        ("oss", "object storage service file"),
    )
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    app = models.ForeignKey('App', on_delete=models.CASCADE)
    name = models.CharField(max_length=63, validators=[validate_label])
    size = models.CharField(default='0G', max_length=128)
    path = models.JSONField(default=dict)
    type = models.CharField(default=TYPE_CHOICES[0][0], choices=TYPE_CHOICES)
    parameters = models.JSONField(default=dict)

    @property
    def pv_name(self):
        md5 = hashlib.md5()
        md5.update(f"{self.app.id}-{self.type}-{self.name}".encode("utf-8"))
        hexdigest = md5.hexdigest()
        return "pvc-{}".format("-".join([
            hexdigest[:8],
            hexdigest[8:12],
            hexdigest[12:16],
            hexdigest[16:20],
            hexdigest[20:]
        ]))

    @property
    def secret_name(self):
        return self.pv_name

    @transaction.atomic
    def save(self, *args, **kwargs):
        if self.type not in settings.DRYCC_VOLUME_CLAIM_TEMPLATE:
            raise DryccException(f'Volume type {self.type} is not supported.')
        # Attach volume, updates k8s
        self.save_to_k8s()
        # check path
        self.check_path()
        # Save to DB
        return super(Volume, self).save(*args, **kwargs)

    @transaction.atomic
    def delete(self, *args, **kwargs):
        # Deatch volume, updates k8s
        self.delete_from_k8s()
        # Delete from DB
        return super(Volume, self).delete(*args, **kwargs)

    def log(self, message, level=logging.INFO):
        """Logs a message in the context of this service.

        This prefixes log messages with an application "tag" that the customized
        drycc-logspout will be on the lookout for.  When it's seen, the message-- usually
        an application event of some sort like releasing or scaling, will be considered
        as "belonging" to the application instead of the controller and will be handled
        accordingly.
        """
        logger.log(level, "[{}]: {}".format(self.app.id, message))

    def to_measurements(self, timestamp: float):
        return [{
            "app_id": str(self.app_id),
            "owner": self.owner_id,
            "name": self.type,
            "type": "volume",
            "unit": "bytes",
            "usage": unit_to_bytes(self.size),
            "kwargs": {
                "name": self.name,
            },
            "timestamp": int(timestamp)
        }]

    def __str__(self):
        return self.name

    def check_path(self, path=None):
        other_volumes = self.app.volume_set.exclude(name=self.name)
        type_paths = {}  # {'type1':[path1,path2], tyep2:[path3,path4]}
        for _ in other_volumes:
            for k, v in _.path.items():
                if k not in type_paths:
                    type_paths[k] = [v]
                else:
                    type_paths[k].append(v)
        items = path.items() if path else self.path.items()
        repeat_path = [v for k, v in items if v in type_paths.get(k, [])]
        if repeat_path:
            msg = "path {} is used by another volume".format(','.join(repeat_path))
            self.log(msg, logging.ERROR)
            raise DryccException(msg)

    def save_to_k8s(self):
        if self.type in settings.DRYCC_SECRET_TEMPLATE:
            self._save_secret()
        if self.type in settings.DRYCC_VOLUME_TEMPLATE:
            self._save_pv()
        self._save_pvc()

    def delete_from_k8s(self):
        if self.type in settings.DRYCC_SECRET_TEMPLATE:
            self._delete_secret()
        if self.type in settings.DRYCC_VOLUME_TEMPLATE:
            self._delete_pv()
        self._delete_pvc()

    @staticmethod
    def _format_size(size):
        """ Format volume limit value """
        if size[-2:-1].isalpha() and size[-1].isalpha():
            size = size[:-1]

        if size[-1].isalpha():
            size = size.upper() + "i"
        return size

    def _save_pv(self):
        kwds = copy.deepcopy(self.parameters.get(self.type, {}))
        kwds.update({
            "volume_claim_name": self.name,
            "namespace": self.app.id,
            "secret_name": self.secret_name,
            "volume_handle": "%s" % uuid.uuid4(),
        })
        t = string.Template(json.dumps(settings.DRYCC_VOLUME_TEMPLATE.get(self.type)))
        kwargs = json.loads(t.safe_substitute(**kwds))
        try:
            self.scheduler().pv.get(self.pv_name)
            msg = "Volume {} already exists".format(self.pv_name)
            self.log(msg, logging.INFO)
            if "csi" in kwargs["spec"]:
                del kwargs["spec"]["csi"]  # Fix: 422 unprocessable Entity
            self.scheduler().pv.patch(self.pv_name, **kwargs)
        except KubeException as e:
            logger.info(e)
            try:
                self.scheduler().pv.create(self.pv_name, **kwargs)
            except KubeException as e:
                msg = 'There was a problem creating the volume ' \
                      '{} for {}'.format(self.pv_name, self.app_id)
                raise ServiceUnavailable(msg) from e

    def _delete_pv(self):
        try:
            # We raise an exception when a volume doesn't exist
            self.scheduler().pv.get(self.pv_name)
            self.scheduler().pv.delete(self.pv_name)
        except KubeException as e:
            logger.exception(e)

    def _save_pvc(self):
        kwds = copy.deepcopy(self.parameters)
        kwds.update({
            "size": self._format_size(self.size),
            "volume_name": self.pv_name,
            "storage_class": settings.DRYCC_APP_STORAGE_CLASS,
        })
        t = string.Template(json.dumps(settings.DRYCC_VOLUME_CLAIM_TEMPLATE.get(self.type)))
        kwargs = json.loads(t.safe_substitute(**kwds))
        try:
            self.scheduler().pvc.get(self.app.id, self.name)
            msg = "Volume claim {} already exists in this namespace".format(self.name)
            self.log(msg, logging.INFO)
            self.scheduler().pvc.patch(self.app.id, self.name, **kwargs)
        except KubeException as e:
            logger.info(e)
            try:
                self.scheduler().pvc.create(self.app.id, self.name, **kwargs)
            except KubeException as e:
                msg = 'There was a problem creating the volume claim ' \
                      '{} for {}'.format(self.name, self.app_id)
                raise ServiceUnavailable(msg) from e

    def _delete_pvc(self):
        try:
            # We raise an exception when a volume doesn't exist
            self.scheduler().pvc.get(self.app.id, self.name)
            self.scheduler().pvc.delete(self.app.id, self.name)
        except KubeException as e:
            logger.exception(e)

    def _save_secret(self):
        kwds = copy.deepcopy(self.parameters.get(self.type, {}))
        t = string.Template(json.dumps(settings.DRYCC_SECRET_TEMPLATE.get(self.type)))
        kwargs = json.loads(t.safe_substitute(**kwds))
        try:
            self.scheduler().secret.get(self.app.id, self.secret_name)
            msg = "Secret {} already exists".format(self.secret_name)
            self.log(msg, logging.INFO)
            self.scheduler().secret.patch(self.app.id, self.secret_name, **kwargs)
        except KubeException as e:
            logger.info(e)
            try:
                self.scheduler().secret.create(self.app.id, self.secret_name, **kwargs)
            except KubeException as e:
                msg = 'There was a problem creating the volume ' \
                      '{} for {}'.format(self.secret_name, self.app_id)
                raise ServiceUnavailable(msg) from e

    def _delete_secret(self):
        try:
            # We raise an exception when a volume doesn't exist
            self.scheduler().secret.get(self.app.id, self.secret_name)
            self.scheduler().secret.delete(self.app.id, self.secret_name)
        except KubeException as e:
            logger.exception(e)

    class Meta:
        get_latest_by = 'created'
        unique_together = (('app', 'name'),)
        ordering = ['-created']
