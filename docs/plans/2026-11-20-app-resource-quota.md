# Workspace App Limit and Default App ResourceQuota Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce a configurable Workspace App limit, provision non-overwriting default App ResourceQuotas, and expose current App quota usage.

**Architecture:** Django settings supply global defaults. `App.save()` serializes and enforces Workspace App counts, while `App.create()` idempotently ensures the fixed `drycc-app` Kubernetes ResourceQuota without modifying existing objects. A read-only App action returns Kubernetes `spec.hard` and `status.used` directly.

**Tech Stack:** Django 5.2, Django REST Framework 3.18, PostgreSQL, Valkey/Redis CacheLock, Kubernetes core v1 ResourceQuota, requests-mock.

**Spec:** `docs/superpowers/specs/2026-11-20-app-resource-quota-design.md`

## Global Constraints

- Follow existing 99-character flake8 limit, single-quote style, model business-logic pattern, and Scheduler resource signatures.
- `DRYCC_WORKSPACE_MAX_APPS=0` and an empty or `{}` `DRYCC_RESOURCE_QUOTA_TEMPLATE` must preserve current behavior; the packaged Chart template enables the documented default quota.
- The managed ResourceQuota is always named `drycc-app`; never patch or replace an existing quota.
- Do not add database migrations, Django signals, quota service classes, or manual URL entries for the App action.
- Do not modify unrelated files or the pre-existing untracked documentation.
- Do not run git commit or any other git mutation without explicit user confirmation.
- Use the project `.venv`; discover local PostgreSQL and Valkey services before choosing test environment overrides.

## Review Focus

- Existing Apps at the Workspace limit must still deploy and scale; pin this in Task 3.
- Existing customized quotas and concurrent create-409 responses must not be overwritten; pin both in Task 2.
- Archived Apps and destination Workspace transfers must consume/enforce App slots; pin both in Task 3.
- Disabled provisioning must not create or delete quotas, while the read API still reads an existing quota; pin these in Tasks 2 and 4.
- Missing `status.used`, raw resource keys, quantities, and viewer permissions must survive the API mapping; pin them in Task 4.

---

### Task 1: Scheduler ResourceQuota Resource

**Files:**
- Create: `rootfs/scheduler/resources/resourcequota.py`
- Create: `rootfs/scheduler/tests/test_resourcequota.py`
- Modify only if required by generic mock behavior: `rootfs/scheduler/mock.py`

**Interfaces:**
- Produces: `scheduler.resourcequotas.get(namespace, name=None, ignore_exception=False, **kwargs)`.
- Produces: `scheduler.resourcequotas.create(namespace, name, ignore_exception=False, **kwargs)` with manifest kwargs such as `spec`.
- Produces a core v1 manifest with `metadata.name`, `metadata.namespace`, `heritage: drycc`, and `spec.hard`.

- [x] **Step 1: Write failing Scheduler tests**

Cover create manifest contents, single get, list get, metadata injection, create failure, and `ignore_exception` behavior. Use quota values `pods='50'` and `requests.cpu='10'` and assert that they remain unchanged.

- [x] **Step 2: Run the new tests and confirm the resource is missing**

Run: `cd rootfs && ../.venv/bin/python manage.py test --settings=api.settings.testing scheduler.tests.test_resourcequota --noinput`
Expected: FAIL because `resourcequotas` is not registered.

- [x] **Step 3: Implement the minimal ResourceQuota resource**

Follow the closest current namespaced resource patterns and the standard `ignore_exception` contract. Implement only manifest, get, and create. Extend the mock only where the new tests prove its generic behavior insufficient.

- [x] **Step 4: Run Scheduler resource tests**

Run the Step 2 command. Expected: PASS.

### Task 2: Default ResourceQuota App Provisioning

**Files:**
- Modify: `rootfs/api/settings/production.py`
- Modify: `rootfs/api/models/app.py`
- Modify: `charts/controller/templates/controller-configmap.yaml`
- Modify: `charts/controller/values.yaml`
- Create: `charts/controller/files/resource-quota-template.json`
- Create: `rootfs/api/tests/test_app_quota.py`

**Interfaces:**
- Consumes: Task 1 `scheduler.resourcequotas.get/create`.
- Produces: `DRYCC_RESOURCE_QUOTA_TEMPLATE[_PATH]` and `App.RESOURCE_QUOTA_NAME = 'drycc-app'`.
- Produces: `App._create_resource_quota() -> None`, called after namespace setup in `App.create()`.
- Produces: `App.quota -> dict | None` (read-only property); returns the quota JSON, `None` on 404, and raises `ServiceUnavailable` on other failures.

- [x] **Step 1: Write failing App provisioning tests**

With `override_settings(DRYCC_RESOURCE_QUOTA_TEMPLATE=...)`, test creation from a rendered template, no create/update when a customized quota exists, repair when absent, concurrent create 409 treated as success, empty settings causing no API calls, and non-404/non-409 failures becoming `ServiceUnavailable`. Add a test proving the `App.quota` property still returns an existing quota when the setting is empty.

- [x] **Step 2: Run provisioning tests and verify failure**

Run: `cd rootfs && ../.venv/bin/python manage.py test --settings=api.settings.testing api.tests.test_app_quota --noinput`
Expected: FAIL because the setting and App methods do not exist.

- [x] **Step 3: Add configuration and App provisioning**

Load the template from its path, render it with Workspace context, and pass the resulting kwargs to the Scheduler. Implement get-or-create after namespace setup, handle create-409 by re-reading, and never patch an existing quota.

- [x] **Step 4: Run provisioning and Scheduler tests**

Run both test modules. Expected: PASS.

### Task 3: Workspace App Limit and Concurrency

**Files:**
- Modify: `rootfs/api/settings/production.py`
- Modify: `rootfs/api/models/app.py`
- Modify: `rootfs/api/tests/test_app_quota.py`

**Interfaces:**
- Produces: non-negative `DRYCC_WORKSPACE_MAX_APPS`, default `10` (zero disables the limit).
- Consumes: existing `CacheLock` with key `workspace:app-quota:{workspace_id}`.
- Preserves: Task 2 `_create_resource_quota()` behavior and existing App update/deploy behavior.

- [x] **Step 1: Write failing App-limit tests**

Test zero/unlimited behavior, two allowed creations and third rejected with 409, independent Workspace counts, archived Apps consuming slots, deletion freeing a slot, destination transfer acceptance/rejection, and an existing App at the limit still deploying/scaling. Add a `DryccTransactionTestCase` concurrency test proving parallel creation never exceeds the configured limit.

- [x] **Step 2: Run limit tests and verify failure**

Run: `cd rootfs && ../.venv/bin/python manage.py test --settings=api.settings.testing api.tests.test_app_quota --noinput`
Expected: new limit cases FAIL because no limit is enforced.

- [x] **Step 3: Implement the model-level limit**

Check only creation and real Workspace changes. Serialize check plus database save with the Workspace CacheLock and release it before `self.create()` or other Kubernetes work. Raise `Conflict` for a full Workspace and `ServiceUnavailable` for lock failure.

- [x] **Step 4: Run limit and existing App tests**

Run `api.tests.test_app_quota` and `api.tests.test_app`. Expected: PASS with no deploy/update regressions.

### Task 4: Quota Read API, Documentation, and Full Verification

**Files:**
- Modify: `rootfs/api/views/app.py`
- Modify: `rootfs/api/serializers/__init__.py`
- Modify: `rootfs/api/tests/test_app_quota.py`
- Modify: `AGENTS.md`

**Interfaces:**
- Consumes: Task 2 `App.quota` property.
- Produces: `GET /v2/apps/{id}/quota/` through an `AppViewSet` GET action.
- Produces: `AppQuotaSerializer` with `name`, `hard`, and `used` fields; `used` defaults to `{}`.

- [x] **Step 1: Write failing API tests**

Assert exact mapping from `metadata.name`, `spec.hard`, and `status.used`; raw `requests.cpu`/`2500m` passthrough; missing `status.used` as `{}`; 404 for absent quota; 503 for Kubernetes failure; viewer access and non-member rejection; and successful reads while automatic provisioning is disabled.

- [x] **Step 2: Run API tests and verify failure**

Run the `api.tests.test_app_quota` module. Expected: new API cases FAIL with 404/405 or missing serializer.

- [x] **Step 3: Implement the model-backed read action and serializer**

Use `self.get_object()` so existing App permissions and archived behavior remain authoritative. Do not add a manual URL, mutate Kubernetes, calculate remaining values, or transform resource keys and quantities.

- [x] **Step 4: Update project conventions**

Document both settings, the fixed `drycc-app` name, lazy repair, and the rule that existing quotas are never overwritten in `AGENTS.md`.

- [x] **Step 5: Run focused and complete verification**

Run `api.tests.test_app_quota`, `api.tests.test_app`, `scheduler.tests.test_resourcequota`, then the full `api scheduler.tests --parallel=8` suite using discovered local services. Run flake8 on changed Python files. Expected: all PASS.

- [x] **Step 6: Inspect the final diff**

Review only the intended files and confirm no migration, Dashboard, RBAC, unrelated documentation, or git history changes were made.
