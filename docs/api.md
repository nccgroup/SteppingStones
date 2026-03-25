# REST API

SteppingStones exposes a REST API for programmatic access to events. All API endpoints are rooted at `/api/`.

## Authentication

The API uses JWT for authentication. Obtain a token pair by posting credentials to `/api/v1/token/`:

```http
POST /api/v1/token/
Content-Type: application/json

{
    "username": "operator",
    "password": "myPa$$w0rd"
}
```

Response:

```json
{
    "access": "<jwt-access-token>",
    "refresh": "<jwt-refresh-token>"
}
```

Include the access token in subsequent requests:

```http
Authorization: Bearer <jwt-access-token>
```

Access tokens expire; use `/api/v1/token/refresh/` to obtain a new one:

```http
POST /api/v1/token/refresh/
Content-Type: application/json

{
    "refresh": "<jwt-refresh-token>"
}
```

## Browsable API

After authenticating to the SteppingStones application in a web browser the API can be browsed at `/api`

## Permissions

All endpoints require the user to be authenticated. Model-level permissions are enforced using Django's standard permission framework based on the entity being accessed, for example for Events:

| HTTP Method | Required Permission  |
|-------------|------------------------------|
| GET         | `event_tracker.view_event`   |
| POST        | `event_tracker.add_event`    |
| PUT / PATCH | `event_tracker.change_event` |
| DELETE      | `event_tracker.delete_event` |

Permissions can be granted via the Django admin interface (`/admin/`).

---

## Endpoints

### API Root

```
GET /api/
```

Returns a discovery index listing links to all top-level API resources.

---

### Events

Full create/read/update/delete access to events.

#### List events

```
GET /api/v1/events/
```

Returns a JSON array of all events.

#### Create an event

```
POST /api/v1/events/
Content-Type: application/json
```

Request body fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `timestamp` | datetime | Yes | Start time of the event (ISO 8601) |
| `timestamp_end` | datetime | No | End time; must be ≥ `timestamp` |
| `operator` | string | No | Username of the operator; defaults to the authenticated user |
| `source` | object | Yes | Context object — see below |
| `target` | object | Yes | Context object — see below |
| `description` | string | Yes | Description of the activity (max 1000 chars) |
| `raw_evidence` | string | No | Free-text evidence |
| `detected` | string | No | Detection outcome: `N/A`, `UNK`, `NEG`, `PAR`, or `FUL` |
| `prevented` | string | No | Prevention outcome: `N/A`, `NEG`, `PAR`, or `FUL` |
| `outcome` | string | No | Outcome notes (max 1000 chars) |
| `mitre_attack_tactic` | string | No | MITRE ATT&CK tactic ID, e.g. `TA0001` |
| `mitre_attack_technique` | string | No | MITRE ATT&CK technique ID, e.g. `T1537`; requires `mitre_attack_tactic` |
| `mitre_attack_subtechnique` | string | No | MITRE ATT&CK sub-technique ID, e.g. `T1498.001`; requires `mitre_attack_technique` |

**Context object** (used for `source` and `target`):

| Field | Type | Description |
|-------|------|-------------|
| `host` | string | Hostname (max 100 chars) |
| `user` | string | Username (max 100 chars) |
| `process` | string | Process name (max 100 chars) |

At least one of `host`, `user`, or `process` must be non-empty. Existing context objects are reused automatically.

Example request:

```json
{
    "timestamp": "2026-03-25T10:00:00Z",
    "source": {"host": "kali", "user": "root"},
    "target": {"host": "dc01.corp.local"},
    "description": "SMB lateral movement via RDP",
    "detected": "NEG",
    "prevented": "NEG",
    "mitre_attack_tactic": "TA0008",
    "mitre_attack_technique": "T1021",
    "mitre_attack_subtechnique": "T1021.001"
}
```

#### Retrieve an event

```
GET /api/v1/events/{id}/
```

#### Update an event

```
PUT /api/v1/events/{id}/
```

Full replacement — all required fields must be supplied.

```
PATCH /api/v1/events/{id}/
```

Partial update — only include fields to change.

#### Delete an event

```
DELETE /api/v1/events/{id}/
```

---

### EventStream (read-only)

Read-only access to events in the compact [EventStream](../event_tracker/static/eventstream/doc-generation.md) format. Useful for feeding events into log ingestion pipelines.

#### List events (EventStream format)

```
GET /api/v1/eventstream/
```

Supports two response formats, selected via the `Accept` header:

| Accept Header | Format |
|---------------|--------|
| `application/json` (default) | JSON array |
| `application/jsonl` | JSON Lines — one JSON object per line |

The JSON Lines format matches SteppingStones' expected format for parsing.

#### Retrieve a single event (EventStream format)

```
GET /api/v1/eventstream/{id}/
```

**EventStream field mapping:**

| API field | Description |
|-----------|-------------|
| `ts` | Start timestamp |
| `te` | End timestamp (omitted if not set) |
| `op` | Operator username |
| `s` | Source context: `h` (host), `u` (user), `p` (process) |
| `t` | Target context: `h`, `u`, `p` |
| `d` | Description |
| `e` | Raw evidence (omitted if empty) |
| `o` | Outcome (omitted if empty) |
| `ma` | MITRE ATT&CK: `ta` (tactic ID), `t` (technique/sub-technique ID); omitted if no MITRE data |

Empty and null fields are suppressed from all EventStream responses.

---

### HashMob-compatible endpoint

SteppingStones emulates the [HashMob](https://hashmob.net) submission API so that hashcat tools already configured for HashMob can submit cracked hashes directly to SteppingStones without reconfiguration.

```
POST /api/hashmob/v2/submit
api-key: <token>
Content-Type: application/json

{
    "algorithm": 1000,
    "founds": ["aad3b435b51404eeaad3b435b51404ee:password123"]
}
```

Authentication uses the `api-key` HTTP header. Tokens are generated automatically and placed in the example .ini file linked to from the password submission web page. The submitting user requires the `event_tracker.change_credential` permission.