# Addon Connection Retrieval Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `GET /v2/apps/{app}/addons/{name}/connection` endpoint that returns the decoded connection Secret of an addon instance.

**Architecture:** Business logic lives in `AddonInstance.get_connection()`. The view delegates to the model and returns raw key-value data. URL routing follows the existing app-scoped addon pattern.

**Tech Stack:** Django 5.2, Django REST Framework 3.16, Kubernetes Python client via `scheduler`, pytest-style Django tests.

## Global Constraints

- Python line length max 99 characters (flake8 in `rootfs/setup.cfg`)
- Single quotes preferred, double quotes for docstrings
- Business logic must live on the model, not in service classes
- Use `DryccException` for business errors
- `AppFilterViewSet` enforces app membership permissions

---

### Task 1: Add `AddonInstance.get_connection()` model method

**Files:**
- Modify: `rootfs/api/models/addon.py`
- Test: `rootfs/api/tests/test_addon.py`

**Interfaces:**
- Consumes: `self.scheduler.addonresources.get(...)`, `self.scheduler.secret.get(...)`
- Produces: `AddonInstance.get_connection() -> dict`

- [ ] **Step 1: Add failing test for `get_connection()`**

```python
from unittest import mock

def test_get_connection(self):
    self._upsert('valkey-abc123')
    s = _mock_connection_scheduler()
    with mock.patch('api.models.addon.get_scheduler', return_value=s):
        instance = AddonInstance.objects.get(name='valkey-abc123')
        data = instance.get_connection()
    self.assertEqual(data, {'host': 'localhost', 'port': '6379'})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/duanhongyi/Sources/controller/rootfs && /home/duanhongyi/Sources/controller/.venv/bin/python manage.py test --settings=api.settings.testing --noinput api.tests.test_addon.AddonInstanceTest.test_get_connection`

Expected: FAIL with `AttributeError: 'AddonInstance' object has no attribute 'get_connection'`

- [ ] **Step 3: Implement `get_connection()` in model**

In `rootfs/api/models/addon.py`, inside class `AddonInstance`, add:

```python
    def get_connection(self):
        """Return decoded connection Secret data for this addon instance."""
        response = self.scheduler.addonresources.get(
            self.app.id, self.name, kind=self.kind, ignore_exception=True)
        if response.status_code == 404:
            raise DryccException(
                f"Addon '{self.name}' resource not found in namespace '{self.app.id}'")
        response.raise_for_status()
        secret_name = response.json().get('status', {}).get('connectionSecretName')
        if not secret_name:
            raise DryccException(
                f"Addon '{self.name}' connection secret is not ready")
        secret_response = self.scheduler.secret.get(self.app.id, secret_name)
        return secret_response.json().get('data', {})
```

- [ ] **Step 4: Add a helper to build a scheduler with connection mocks**

In `rootfs/api/tests/test_addon.py`, add a helper after `_mock_scheduler()`:

```python
def _mock_connection_scheduler(data=None, secret_name='valkey-abc123-connection'):
    s = _mock_scheduler()
    cr = mock.Mock()
    cr.status_code = 200
    cr.json.return_value = {
        'status': {'connectionSecretName': secret_name},
    }
    s.addonresources.get = mock.Mock(return_value=cr)

    secret = mock.Mock()
    secret.status_code = 200
    secret.json.return_value = {
        'data': data if data is not None else {'host': 'localhost', 'port': '6379'},
    }
    s.secret.get = mock.Mock(return_value=secret)
    return s
```

- [ ] **Step 5: Run the test**

Run: `cd /home/duanhongyi/Sources/controller/rootfs && /home/duanhongyi/Sources/controller/.venv/bin/python manage.py test --settings=api.settings.testing --noinput api.tests.test_addon.AddonInstanceTest.test_get_connection`

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add rootfs/api/models/addon.py rootfs/api/tests/test_addon.py
git commit -m "feat(addon): add AddonInstance.get_connection() model method"
```

---

### Task 2: Implement `AddonConnectionViewSet` retrieve endpoint

**Files:**
- Modify: `rootfs/api/views/addon.py`
- Test: `rootfs/api/tests/test_addon.py`

**Interfaces:**
- Consumes: `AddonInstance.get_connection()`
- Produces: `GET /v2/apps/{app}/addons/{name}/connection` returns `200 OK` with decoded Secret data

- [ ] **Step 1: Add failing test for the endpoint**

```python
def test_retrieve_addon_connection(self):
    from unittest import mock
    self._upsert('valkey-abc123')
    s = _mock_connection_scheduler()
    with mock.patch('api.models.base.get_scheduler', return_value=s):
        response = self.client.get(
            '/v2/apps/{}/addons/valkey-abc123/connection'.format(self.app_id))
    self.assertEqual(response.status_code, 200, response.data)
    self.assertEqual(response.data, {'host': 'localhost', 'port': '6379'})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/duanhongyi/Sources/controller/rootfs && /home/duanhongyi/Sources/controller/.venv/bin/python manage.py test --settings=api.settings.testing --noinput api.tests.test_addon.AddonInstanceTest.test_retrieve_addon_connection`

Expected: FAIL with 404 (route not registered)

- [ ] **Step 3: Implement `AddonConnectionViewSet.retrieve`**

In `rootfs/api/views/addon.py`, update the existing class:

```python
class AddonConnectionViewSet(AppFilterViewSet):
    """A viewset for addon connection scoped under an application."""

    def get_object(self):
        app = self.get_app()
        instance = get_object_or_404(
            models.addon.AddonInstance, app=app, name=self.kwargs['name'])
        return instance.get_connection()

    def retrieve(self, request, *args, **kwargs):
        data = self.get_object()
        return Response(data, status=status.HTTP_200_OK)
```

- [ ] **Step 4: Run the test**

Run: `cd /home/duanhongyi/Sources/controller/rootfs && /home/duanhongyi/Sources/controller/.venv/bin/python manage.py test --settings=api.settings.testing --noinput api.tests.test_addon.AddonInstanceTest.test_retrieve_addon_connection`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add rootfs/api/views/addon.py rootfs/api/tests/test_addon.py
git commit -m "feat(addon): implement AddonConnectionViewSet retrieve endpoint"
```

---

### Task 3: Register the URL route

**Files:**
- Modify: `rootfs/api/urls.py`
- Test: `rootfs/api/tests/test_addon.py`

**Interfaces:**
- Consumes: `views.AddonConnectionViewSet`
- Produces: `GET /v2/apps/{app}/addons/{name}/connection`

- [ ] **Step 1: Add route in `rootfs/api/urls.py`**

After the existing addon instance routes, add:

```python
    # addon connection
    re_path(
        r"^apps/(?P<id>{})/addons/(?P<name>[a-z0-9]([a-z0-9-]*[a-z0-9])?)/connection/?$".format(
            settings.APP_URL_REGEX),
        views.AddonConnectionViewSet.as_view({'get': 'retrieve'}),
    ),
```

- [ ] **Step 2: Run the endpoint test again**

Run: `cd /home/duanhongyi/Sources/controller/rootfs && /home/duanhongyi/Sources/controller/.venv/bin/python manage.py test --settings=api.settings.testing --noinput api.tests.test_addon.AddonInstanceTest.test_retrieve_addon_connection`

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add rootfs/api/urls.py
git commit -m "feat(urls): register addon connection endpoint"
```

---

### Task 4: Add error handling tests

**Files:**
- Modify: `rootfs/api/tests/test_addon.py`

- [ ] **Step 1: Add test for missing `connectionSecretName`**

```python
def test_retrieve_addon_connection_not_ready(self):
    from unittest import mock
    self._upsert('valkey-abc123')
    s = _mock_scheduler()
    cr = mock.Mock()
    cr.status_code = 200
    cr.json.return_value = {'status': {}}
    s.addonresources.get = mock.Mock(return_value=cr)
    with mock.patch('api.models.base.get_scheduler', return_value=s):
        response = self.client.get(
            '/v2/apps/{}/addons/valkey-abc123/connection'.format(self.app_id))
    self.assertEqual(response.status_code, 400, response.data)
```

- [ ] **Step 2: Run the test**

Run: `cd /home/duanhongyi/Sources/controller/rootfs && /home/duanhongyi/Sources/controller/.venv/bin/python manage.py test --settings=api.settings.testing --noinput api.tests.test_addon.AddonInstanceTest.test_retrieve_addon_connection_not_ready`

Expected: PASS

- [ ] **Step 3: Add test for CR not found**

```python
def test_retrieve_addon_connection_resource_missing(self):
    from unittest import mock
    self._upsert('valkey-abc123')
    s = _mock_scheduler()
    cr = mock.Mock()
    cr.status_code = 404
    s.addonresources.get = mock.Mock(return_value=cr)
    with mock.patch('api.models.base.get_scheduler', return_value=s):
        response = self.client.get(
            '/v2/apps/{}/addons/valkey-abc123/connection'.format(self.app_id))
    self.assertEqual(response.status_code, 400, response.data)
```

- [ ] **Step 4: Run the test**

Run: `cd /home/duanhongyi/Sources/controller/rootfs && /home/duanhongyi/Sources/controller/.venv/bin/python manage.py test --settings=api.settings.testing --noinput api.tests.test_addon.AddonInstanceTest.test_retrieve_addon_connection_resource_missing`

Expected: PASS

- [ ] **Step 5: Run the full addon test suite**

Run: `cd /home/duanhongyi/Sources/controller/rootfs && /home/duanhongyi/Sources/controller/.venv/bin/python manage.py test --settings=api.settings.testing --noinput api.tests.test_addon`

Expected: All tests in `api.tests.test_addon` PASS

- [ ] **Step 6: Commit**

```bash
git add rootfs/api/tests/test_addon.py
git commit -m "test(addon): add error handling tests for connection endpoint"
```

---

## Self-Review Checklist

- [ ] Spec coverage: endpoint, model method, URL route, tests all mapped to tasks
- [ ] Placeholder scan: no TBD/TODO or vague steps
- [ ] Type consistency: `get_connection()` returns `dict`; view returns `Response`
- [ ] Test commands use the project's `.venv` Python and `api.settings.testing`
