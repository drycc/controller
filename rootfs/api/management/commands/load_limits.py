from django.core.management.commands import loaddata
from api.models.limit import LimitSpec, LimitPlan


class Command(loaddata.Command):

    def save_obj(self, obj):
        if obj.__class__ in (LimitSpec, LimitPlan):
            obj.__class__.objects.filter(id=obj.id).delete()
            return super().save_obj(obj)
        return False
