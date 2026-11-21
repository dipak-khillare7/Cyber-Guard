# Database Schema Documentation

## Entities & Relationships

### 1. `security_events`
Stores ingested raw network flow events and security log entries.
* `id` (INT, Primary Key, Auto-increment)
* `timestamp` (DATETIME, Indexed, Default UTC Now)
* `source_ip` (VARCHAR(45), Indexed, Nullable)
* `destination_ip` (VARCHAR(45), Indexed, Nullable)
* `source_port` (INT, Nullable)
* `destination_port` (INT, Nullable)
* `protocol` (VARCHAR(20), Indexed, Default 'TCP')
* `duration` (FLOAT, Connection duration in seconds)
* `packet_count` (INT, Total packets)
* `byte_count` (INT, Total bytes)
* `event_type` (VARCHAR(50), NETWORK / SYSTEM / AUTH / LOG)
* `raw_data` (TEXT, Raw log text or payload)
* `created_at` (DATETIME)

### 2. `alerts`
Stores threat detection alerts generated from security events.
* `id` (INT, Primary Key, Auto-increment)
* `event_id` (INT, Foreign Key -> `security_events.id`, Nullable, SET NULL on delete)
* `threat_type` (VARCHAR(50), Enum category)
* `confidence` (FLOAT, Score 0.0 - 1.0)
* `risk_level` (VARCHAR(20), LOW / MEDIUM / HIGH / CRITICAL)
* `message` (TEXT, Alert description)
* `status` (VARCHAR(20), NEW / ACKNOWLEDGED / RESOLVED / IGNORED)
* `created_at` (DATETIME)

### 3. `incidents`
Tracks escalated security incidents requiring response.
* `id` (INT, Primary Key, Auto-increment)
* `alert_id` (INT, Foreign Key -> `alerts.id`, Nullable, SET NULL on delete)
* `threat_type` (VARCHAR(50))
* `severity` (VARCHAR(20), LOW / MEDIUM / HIGH / CRITICAL)
* `description` (TEXT)
* `status` (VARCHAR(20), OPEN / IN_PROGRESS / RESOLVED / CLOSED)
* `assigned_to` (VARCHAR(100), Handler username)
* `created_at` (DATETIME)
* `resolved_at` (DATETIME, Nullable)

### 4. `response_actions`
Records mitigation response actions executed in safe simulation mode.
* `id` (INT, Primary Key, Auto-increment)
* `incident_id` (INT, Foreign Key -> `incidents.id`, CASCADE on delete)
* `action_type` (VARCHAR(50), LOG / ALERT / SIMULATED_BLOCK / SIMULATED_ISOLATION / ESCALATE)
* `action_status` (VARCHAR(20), Default SIMULATED)
* `description` (TEXT)
* `executed_at` (DATETIME)

### 5. `rate_limit_buckets`
Stores fixed-window request counters shared by application instances using the same SQL database. The bucket key is an HMAC digest; raw IP addresses, user identifiers, and email addresses are not stored.
* `bucket_key` (VARCHAR(64), Primary Key)
* `window_start` (INT, Window start timestamp)
* `hit_count` (INT, Number of requests in the window)
