# Drycc Controller — Agent Instructions

## Project Structure

```
controller/
  rootfs/
    api/                    # Django application
      models/               # Django models (one file per domain)
      views/                # DRF ViewSets (one file per domain)
      serializers/          # DRF serializers (__init__.py contains all)
      migrations/           # Django migrations
      tests/                # Unit tests (test_*.py)
      settings/             # Django settings (production.py, testing.py)
      clients.py            # External service API clients
      exceptions.py         # Custom exception classes
      urls.py               # URL routing
      viewsets.py           # Base ViewSet classes
      utils.py              # Helper functions
      tasks.py              # Celery tasks
    scheduler/              # Kubernetes API client
      __init__.py           # KubeHTTPClient (base HTTP layer)
      resources/            # K8s resource implementations
      exceptions.py         # KubeException, KubeHTTPException
    manage.py               # Django management script
    requirements.txt        # Python dependencies
    setup.cfg               # flake8 config
  Makefile                  # Build/test commands
```

## Code Style

- **Indentation**: 4 spaces (see `.editorconfig`)
- **Line endings**: LF
- **Line length**: 99 characters max (see `setup.cfg` flake8)
- **Complexity**: max 12 (flake8)
- **Formatter**: None configured — follow existing file style exactly
- **Quotes**: Single quotes preferred, double quotes for docstrings
- **Trailing commas**: Follow existing file patterns

### Flake8 Excludes

`api/migrations`, `templates`, `venv` — never lint these.

## Model Conventions

### Base Classes

- `UuidAuditedModel` — UUID primary key + `created`/`updated` timestamps (most models)
- `AuditedModel` — Just `created`/`updated` timestamps

### Field Ordering

1. Primary key (uuid from base class, or custom like `id = models.SlugField`)
2. Business fields
3. Foreign keys
4. JSON fields
5. Meta class last

### Model Methods

- `save(*args, **kwargs)` — Override for K8s resource creation. Call `super().save()` first, then K8s ops if creating (`self._state.adding`).
- `delete(*args, **kwargs)` — Override for K8s cleanup. Clean K8s first, then `super().delete()`.
- `scheduler` property — Returns `get_scheduler(metadata={...})` with labels/annotations. Use this for all K8s operations.
- Helper methods prefixed with `_` (private).
- Business logic methods as instance methods on the model (NO separate Service classes).

### Validation Functions

- Module-level `validate_*` functions, used in field `validators=[]`
- Raise `rest_framework.exceptions.ValidationError`

### Example

```python
class MyModel(UuidAuditedModel):
    name = models.CharField(max_length=63)
    workspace = models.ForeignKey("Workspace", on_delete=models.CASCADE)
    
    class Meta:
        unique_together = [("workspace", "name")]
    
    def __str__(self):
        return self.name
    
    @property
    def scheduler(self):
        labels = {"drycc.cc/workspace": self.workspace.id}
        return get_scheduler(metadata={"labels": labels, "annotations": dict(labels)})
    
    def save(self, *args, **kwargs):
        creating = self._state.adding
        if creating:
            # validate, set derived fields
            pass
        super().save(*args, **kwargs)
        if creating:
            # K8s operations via self.scheduler
            pass
    
    def delete(self, *args, **kwargs):
        # K8s cleanup first
        try:
            self.scheduler.something.delete(...)
        except KubeException:
            pass
        return super().delete(*args, **kwargs)
    
    def update_something(self, params):
        # business logic + K8s update
        pass
```

## View Conventions

### Base Classes

- `ModelViewSet` — Standard CRUD
- `AppFilterViewSet` — App-scoped resources (nested under apps)
- Views are split into separate files under `api/views/`

### ViewSet Structure

```python
class MyModelViewSet(ModelViewSet):
    lookup_field = 'name'  # or 'id'
    lookup_value_regex = r'[a-z0-9]([a-z0-9-]*[a-z0-9])?'
    serializer_class = serializers.MyModelSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        queryset = models.mymodel.MyModel.objects.filter(
            workspace__workspacemember__user=self.request.user).distinct()
        workspace = self.request.query_params.get('workspace')
        if workspace:
            workspace_obj = get_object_or_404(
                models.workspace.Workspace, id=workspace)
            if not workspace_obj.has_member(self.request.user):
                raise PermissionDenied(
                    f"You are not a member of workspace '{workspace_obj.id}'")
            queryset = queryset.filter(workspace=workspace_obj)
        return queryset
    
    def get_object(self):
        return get_object_or_404(self.get_queryset(), name=self.kwargs['name'])
    
    def create(self, request, *args, **kwargs):
        # Extract workspace from request.data['workspace']
        # Create model instance directly, call instance.save()
        # Return serialized response
        pass
    
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.update_something(request.data)
        serializer = self.get_serializer(instance)
        return Response(serializer.data)
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
```

### Flat Workspace Pattern

Workspace management is **flat**. Resources are NOT nested under `/workspaces/{id}/`.
Instead, they live at top-level endpoints and filter via `?workspace=` query param:

- `GET /v2/addons?workspace=myworkspace` — list filtered by workspace
- `POST /v2/addons` with `{"workspace": "myworkspace", ...}` — create in workspace

See `AppViewSet.list()` for the reference pattern.

### NO Service Classes

All business logic goes on the model itself. The view calls model methods directly.
This is the established pattern — see `App.create()`, `App.delete()`, etc.

### Error Handling in Views

- `DryccException("message")` — 400 status, business errors
- `ValidationError("message")` — 400 status, validation errors
- `AlreadyExists` — 409 status
- `PermissionDenied("message")` — 403 status
- `get_object_or_404()` — 404 status

**DO NOT** create domain-specific exception classes (e.g., `AddonNotFound`). Use `DryccException` with descriptive messages.

## Serializer Conventions

All serializers live in `api/serializers/__init__.py`.

```python
class MyModelSerializer(serializers.ModelSerializer):
    workspace = serializers.ReadOnlyField(source='workspace.id')
    
    class Meta:
        model = models.mymodel.MyModel
        fields = ['uuid', 'name', 'workspace', 'created', 'updated']
        read_only_fields = ['uuid', 'created', 'updated']
```

## URL Conventions

URLs use `re_path` in `api/urls.py`. Workspace-managed resources are **flat** at top-level:

```python
re_path(r'^addons/?$',
        views.AddonInstanceViewSet.as_view({'get': 'list', 'post': 'create'}),
        name='addon_list'),
re_path(r'^addons/(?P<name>[-_\w]+)/?$',
        views.AddonInstanceViewSet.as_view(
            {'get': 'retrieve', 'put': 'update', 'patch': 'update', 'delete': 'destroy'}),
        name='addon_detail'),
```

Workspace sub-resources (members, invitations) are nested under `/workspaces/{id}/`:

```python
re_path(r'^workspaces/(?P<id>[-_\w]+)/members/?$',
        views.WorkspaceMemberViewSet.as_view({'get': 'list'}),
        name='workspace_member_list'),
```

- Item lookup uses `name` kwarg (not `id`)
- Trailing `/?` for optional slash
- Flat resources filter via `?workspace=` query param

## Scheduler / K8s Conventions

### Resource Pattern

All resources in `scheduler/resources/` extend `Resource` base class:

```python
class MyResource(Resource):
    api_prefix = 'apis'  # or 'api' for core v1
    api_version = 'group/v1'
    short_name = 'myresources'  # optional, for KubeHTTPClient mapping
    
    def get(self, namespace, name=None, ignore_exception=True, **kwargs):
        url = self.api("/namespaces/{}/myresource/{}", namespace, name)
        response = self.http_get(url, params=self.query_params(**kwargs))
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, 'get MyResource ' + name)
        return response
    
    def create(self, namespace, name, ignore_exception=True, **kwargs):
        manifest = kwargs["manifest"]
        url = self.api("/namespaces/{}/myresource", namespace)
        response = self.http_post(url, json=manifest)
        if not ignore_exception and self.unhealthy(response.status_code):
            raise KubeHTTPException(response, 'create MyResource "{}"', name)
        return response
```

### Standard Method Signatures

**Namespaced resources:**

```python
def get(self, namespace, name=None, ignore_exception=True, **kwargs)
def create(self, namespace, name, ignore_exception=True, **kwargs)
def put(self, namespace, name, ignore_exception=True, **kwargs)
def patch(self, namespace, name, ignore_exception=True, **kwargs)
def delete(self, namespace, name, ignore_exception=True, **kwargs)
```

**Cluster-scoped resources** (e.g. `AddonClass`, `Node`, `Namespace`) omit `namespace`:

```python
def get(self, name=None, ignore_exception=True, **kwargs)
def create(self, name, ignore_exception=True, **kwargs)
def delete(self, name, ignore_exception=True, **kwargs)
```

- `namespace` — first positional arg (namespaced resources only)
- `name` — positional arg (optional for `get`)
- `ignore_exception` — controls error raising
- `**kwargs` — for resource-specific parameters (manifest, kind, etc.)

### get() Handles Both Single and List

**NEVER** create a separate `list()` method. When `name=None`, `get()` returns a list of all resources; when `name` is provided, it returns a single resource.

```python
def get(self, name=None, ignore_exception=True):
    url = self.api("/addonclasses")
    args = []
    if name is not None:
        args.append(name)
        url += "/{}"
        message = 'get AddonClass "{}"'
    else:
        message = 'get AddonClasses'
    url = self.api(url, *args)
    response = self.http_get(url)
    if not ignore_exception and self.unhealthy(response.status_code):
        raise KubeHTTPException(response, message, *args)
    return response
```

### Required kwargs

When a kwarg is required (e.g. `kind` for generic resource handlers), validate explicitly and raise `KubeException`:

```python
kind = kwargs.pop("kind", None)
if kind is None:
    raise KubeException("kind is required for AddonResource operations")
```

**NEVER** put resource-specific params like `kind`, `manifest` as positional args. Use `**kwargs`.

Use `kwargs.pop()` if the value should NOT be passed to K8s query_params (e.g., `kind`).
Use `kwargs.get()` if it's fine to pass through.

### Accessing Resources

Resources are auto-registered and accessible via `scheduler_client.<plural_name>`:
- `scheduler.deployments` → Deployment resource
- `scheduler.addonresources` → AddonResource (generic Crossplane composite resource handler, `kind` required)
- `scheduler.addonclasses` → AddonClass resource

### Exception Handling

- `KubeException` — General K8s error
- `KubeHTTPException` — HTTP-level K8s error (has `.response` attribute)
- `ignore_exception=True/False` — Controls whether errors raise or are suppressed

## Migration Conventions

- Manual migration files in `api/migrations/`
- Numbered sequentially: `0033_xxx.py`
- If `makemigrations` fails due to serialization issues (e.g., complex validators), write the migration manually
- Dependencies: `('api', '0032_previous')`

## Test Conventions

### Base Classes

- `DryccTestCase` — TransactionTestCase with K8s mocking
- `DryccTransactionTestCase` — TransactionTestCase variant
- Both use `@requests_mock.Mocker(real_http=True, adapter=adapter)` decorator

### Test Structure

```python
@requests_mock.Mocker(real_http=True, adapter=adapter)
class MyModelTest(DryccTestCase):
    fixtures = ['tests.json']
    
    def setUp(self):
        self.user = User.objects.get(username='autotest')
        self.token = self.get_or_create_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
    
    def test_something(self, mock_requests):
        # test implementation
        pass
```

### Running Tests

**Local testing:** Use the project's `.venv` at the project root.

```bash
cd rootfs
../.venv/bin/python manage.py test --settings=api.settings.testing --noinput api scheduler.tests
```

**Makefile targets:** (run inside podman container with test image)
```bash
make test          # style + unit + functional
make test-style    # flake8 + shellcheck
make test-unit     # Django unit tests
```

## Vibe Coding Rules

- **Write tests alongside code.** Every new feature, model, view, or serializer must have corresponding test cases in `api/tests/test_<name>.py`.
- **Do not commit code without tests.** If you implement a new endpoint, model method, or scheduler resource, add tests that verify the behavior.
- **Run tests locally before reporting completion.** Use the `.venv` Python interpreter from the project root to run `api.scheduler.tests`.

## Import Conventions

```python
# Standard library (alphabetical)
import logging
import re
import uuid

# Third-party
from django.db import models
from rest_framework.exceptions import ValidationError

# Internal - api package
from api.utils import validate_reserved_names, get_scheduler
from api.exceptions import DryccException, AlreadyExists
from scheduler import KubeHTTPException, KubeException

# Internal - relative (models only)
from .base import UuidAuditedModel

# User model
User = get_user_model()
logger = logging.getLogger(__name__)
```

## Workspace Namespace

- `Workspace.namespace` property returns `f"{settings.WORKSPACE_NAMESPACE_PREFIX}{self.id}"`
- Default prefix: `drycc-workspace-`
- Configurable via `WORKSPACE_NAMESPACE_PREFIX` env var
- Use `workspace.namespace` for all K8s namespace references

## Dependencies

- Django 5.2.x
- Django REST Framework 3.16.x
- PostgreSQL (via psycopg)
- Celery + Redis
- Kubernetes Python client
- requests + requests-toolbelt
- jsonschema for validation

## Key Settings

| Setting | Default | Purpose |
|---|---|---|
| `WORKFLOW_NAMESPACE` | `drycc` | Controller's own namespace |
| `WORKSPACE_NAMESPACE_PREFIX` | `drycc-workspace-` | Workspace namespace prefix |
| `SCHEDULER_MODULE` | `scheduler` | K8s client module |
| `SCHEDULER_URL` | from env | K8s API URL |
| `K8S_API_VERIFY_TLS` | `true` | TLS verification |
| `APP_URL_REGEX` | `[a-z0-9-]+` | App name URL pattern |
| `NAME_REGEX` | `[a-z0-9]+(\-[a-z0-9]+)*` | Resource name URL pattern |
