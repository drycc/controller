# Controller Commercial Status Client Design

**Date:** 2026-11-18
**Status:** Workspace status conversion implemented; response hardening remains target architecture

## 1. Purpose

Preserve Controller's existing ManagerAPI User commercial status check and
replace the App status check with a Workspace status check, allowing Dashboard
v2 to resolve the current Organization and Payment through the Cluster-scoped
URL and Controller Workspace slug.

workflow-cli and controller-sdk-go remain direct Controller clients. They do not
use a Dashboard proxy and require no Cluster header, Cluster profile contract,
or Builder behavior change. The status integration is entirely server-to-server
between Controller and Dashboard.

The authoritative cross-component contract is the sibling Workflow repository's
`docs/superpowers/specs/2026-11-13-organization-billing-integration-design.md`.

## 2. Verified Current Behavior

Controller currently:

- calls `ManagerAPI.get_user_status(user.id)` during Token/Bearer
  authentication;
- calls `ManagerAPI.get_workspace_status(app.workspace.id)` from
  `HasAppAccess` for Apps and App subresources;
- uses the same Workspace status method from Hooks and `AppPermChecker` through
  `HasAppAccess`;
- sends requests below the configured Cluster-scoped `WORKFLOW_MANAGER_URL`;
- expects `{"is_active": boolean, "message": string}`;
- caches status responses and returns a fail-open result on timeout.

The Workspace request contains `Workspace.id`, which is the SlugField shown in
API URLs. It must not contain `app.workspace_id`: because Workspace inherits
`UuidAuditedModel`, that foreign-key attribute contains the Workspace UUID.

The latest Manager contract has no App status resource. Apps inherit their
commercial status from the Workspace that owns them.

## 3. Decisions

- Keep the existing Controller call sites and ManagerAPI status responsibility.
- Replace App status with Workspace status and pass `app.workspace.id`, the
  Workspace SlugField, rather than an App identifier or Workspace UUID.
- Resolve Cluster from the existing Cluster-scoped Manager URL, not an event or
  CLI header.
- Key Workspace status cache entries by resource type and Workspace slug.
- Keep User status account/platform-scoped. One Organization's delinquency must
  not disable a User across all Workspaces and Organizations.
- Let Dashboard apply Organization/Payment policy to Workspace commercial
  status without changing Controller's local Workspace membership or resource
  roles.
- Preserve fail-open behavior for transient Dashboard unavailability, including
  timeout, connection failure, and HTTP 5xx. Do not silently turn authentication
  failures, other 4xx responses, or malformed payloads into a successful status.

## 4. ManagerAPI Interface

`rootfs/api/clients.py` exposes the following logical interfaces:

```python
get_status(
    resource_type: str,
    resource_id: str,
) -> tuple[bool, str | None]

get_workspace_status(workspace_id: str) -> tuple[bool, str | None]

get_user_status(user_id: str) -> tuple[bool, str | None]
```

`get_user_status()` retains its current public behavior.
`get_workspace_status()` delegates to `get_status("workspace", workspace_id)`.

When `WORKFLOW_MANAGER_URL` is unset, all methods retain the current enabled
check and return `(True, None)`, preserving community behavior.

## 5. HTTP Contract

Given a configured Manager base URL such as:

```text
https://dashboard.example.test/v1/clusters/{cluster_id}
```

Controller requests:

```text
GET {WORKFLOW_MANAGER_URL}/users/{user_id}/status/
GET {WORKFLOW_MANAGER_URL}/workspaces/{workspace_id}/status/
```

`workspace_id` is the Controller `Workspace.id` SlugField. There is no App
identifier, Workspace UUID, or `workspace` query parameter in this request.

Dashboard authenticates the Controller service request through the shared
Passport, resolves the Cluster from the matched route, and resolves the
Workspace and its Organization/Payment from the Cluster and Workspace slug.

A successful response is HTTP 200 with exactly the required semantics:

```json
{
  "is_active": false,
  "message": "The Organization Payment is suspended."
}
```

Dashboard returns a valid `is_active=false` response for an unknown, unbound,
or commercially ineligible Workspace according to policy; it must not treat an
unknown Workspace as paid or fall back to an App owner or User Payment.

User status evaluates account/platform eligibility only. Workspace commercial
status may evaluate the bound Organization/Payment, but local Controller
authorization still runs independently and is never replaced by that response.

## 6. Controller Callers

### 6.1 HTTP resources and Hooks

`HasAppAccess` in `rootfs/api/permissions.py` uses the resolved App's Workspace
slug:

```python
get_workspace_status(app.workspace.id)
```

This applies to App and App-subresource object checks and to Hooks after
resolving the local App. Existing Workspace membership, method/role, and App
archive checks remain unchanged.

### 6.2 WebSockets

`AppPermChecker` already delegates to `HasAppAccess`, so it uses the same
Workspace status check without a separate ManagerAPI call or Consumer-specific
implementation. Its existing outer permission-cache behavior is unchanged by
this conversion.

## 7. Response and Failure Handling

`get_status()` validates that:

- the HTTP response is successful;
- the body is a JSON object;
- `is_active` is a boolean;
- `message`, when present, is a string suitable for an error response.

Failure behavior:

| Condition | Controller behavior |
| --- | --- |
| Manager integration disabled | Return `(True, None)` |
| Valid `is_active=true` | Allow the commercial status check and cache the response |
| Valid `is_active=false` | Deny with the returned message; local permission checks still apply |
| Timeout, connection failure, or HTTP 5xx | Return transient fail-open, log a sanitized error, and do not cache the result |
| Authentication failure, other 4xx, or invalid response | Raise `ServiceUnavailable`; do not convert it to active |
| Log or exception content | Never include Passport tokens, Authorization headers, or secrets |

Transient fail-open is a commercial availability decision, not a Workspace
permission grant. The existing local User/App authorization still protects the
resource. A transient fail-open result is not cached, preventing one outage
from hiding later recovery or a later Payment suspension for the normal cache
TTL.

Only well-formed HTTP 200 responses are cached. This deliberately tightens the
current behavior that can otherwise treat an arbitrary JSON response without
`is_active` as active.

## 8. Cache Identity

ManagerAPI Workspace status-cache identity includes:

```text
resource type = workspace
Workspace slug
```

User status-cache identity remains resource type plus User ID. The WebSocket
outer permission cache remains unchanged by this conversion.

Payment or binding changes remain subject to the existing documented cache TTL;
shortening that TTL or adding active invalidation is a separate operational
policy and is not silently changed by this design. Different Workspace slugs
always produce different ManagerAPI status-cache keys.

## 9. Dashboard Resolution Rules

Dashboard implements the endpoint internals described in its own commercial
control-plane design. For Workspace status it must:

1. authenticate the Controller service request;
2. resolve the Cluster from the matched Cluster-scoped route;
3. validate the Workspace slug;
4. resolve the Workspace for the Cluster/Workspace-slug pair;
5. resolve the bound Organization and its active Payment or commercial hold;
6. return an explicit status and sanitized message.

No binding, overlapping or ambiguous binding state, archived Organization, or
missing Payment must be handled according to explicit commercial policy rather
than assumed paid. Dashboard does not derive the Organization from an App or a
User owner.

## 10. File Boundaries

Modify:

- `rootfs/api/clients.py` — Workspace status method and Cluster-scoped request;
- `rootfs/api/permissions.py` — pass the owning Workspace SlugField;
- `rootfs/api/tests/test_clients.py` — exact Workspace status URL regression;
- `rootfs/api/tests/test_app_archive.py` — App, Hook, and shared permission
  behavior using Workspace status;
- `rootfs/api/tests/test_authentication.py` — unchanged User status contract
  and direct authentication regression;
- `AGENTS.md` — implemented contract and verification commands when code lands.

No Workspace model, Membership model, App foreign key, SDK, CLI, Passport,
Builder, or Chart schema change is required. The existing Manager URL and
Passport service authentication are reused.

## 11. Verification

The implemented conversion covers:

- App permission and Hook checks pass the exact Workspace SlugField;
- Dashboard receives
  `/v1/clusters/{cluster_id}/workspaces/{workspace_id}/status/`;
- valid active/inactive responses and sanitized messages retain their behavior;
- User authentication and usage reporting remain unchanged;
- no App status request or Workspace UUID is substituted for the slug.

The response-hardening target additionally covers:

- community mode returns active without HTTP;
- timeout, connection failure, and 5xx return uncached transient fail-open;
- authentication failures, other 4xx, malformed JSON, missing `is_active`, and
  non-boolean `is_active` produce `ServiceUnavailable` rather than active;
- User status is not changed by one Organization's Payment state;
- direct CLI/SDK behavior requires no Dashboard proxy or Cluster header;
- Authorization headers, OAuth bundles, and secrets never appear in logs.

Run focused tests followed by the complete Controller and Scheduler suites:

```bash
cd rootfs
../.venv/bin/python manage.py test --settings=api.settings.testing --noinput \
  api.tests.test_clients api.tests.test_app_archive api.tests.test_authentication
../.venv/bin/python manage.py test --settings=api.settings.testing --noinput \
  api scheduler.tests
```

Cross-repository acceptance must additionally verify Organization/Payment status,
unknown binding behavior, transient Dashboard outage, and direct CLI access
against a real Dashboard v2 Workspace status endpoint.

## 12. Implementation Sequence

1. Add failing ManagerAPI Workspace URL and permission-caller tests.
2. Replace App status with Workspace status using the Workspace SlugField.
3. Run focused and complete Controller regression suites.
4. Implement the response validation and failure-handling target separately.
5. Live-test the corresponding Dashboard Workspace status endpoint.
