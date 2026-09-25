# IKE-UI API

API v1 provides integration endpoints for the panel. The available endpoints currently manage VPN user accounts.

## Base URL

Use the Base URL shown in Settings → API:

```text
https://your-domain.example/api/v1
```

## Authentication

Send the API key on every request with either header:

```http
X-API-Key: sk-your-key
```

or:

```http
Authorization: Bearer sk-your-key
```

The full `sk-` key is shown only once when an administrator creates it. Store it securely. The panel stores only a hash and cannot recover a lost key.

## Endpoints

| Method | Path | Description |
| --- | --- | --- |
| GET | `/stats` | Get dashboard statistics and current system metrics. |
| GET | `/ping` | Ping the panel to test connectivity, response time, and authentication. |
| GET | `/users` | List users. Query: `q`, `page`, `per_page`. |
| POST | `/users` | Create a user. |
| GET | `/users/{id}` | Get one user. |
| PATCH / PUT | `/users/{id}` | Edit user fields. |
| POST | `/users/{id}/password` | Change password. |
| POST | `/users/{id}/status` | Enable or disable a user. |
| POST | `/users/{id}/reset-traffic` | Reset consumed traffic for a user back to 0. |
| DELETE | `/users/{id}` | Delete user and disconnect active sessions. |
| GET | `/backup/users` | Download a users-only SQLite backup file. |
| POST | `/restore/users` | Restore user accounts from an SQLite database backup file. |
| GET | `/system/update/check` | Check GitHub for official stable releases. Query: `force`. |
| POST | `/system/update` | Trigger background update to the latest official stable release. |

## Dashboard statistics

```bash
curl 'https://your-domain.example/api/v1/stats' \
  -H 'X-API-Key: sk-your-key'
```

Example response:

```json
{
  "success": true,
  "version": "1.9.4",
  "stats": {
    "total_accounts": 11,
    "active_users": 11,
    "online_users": 6,
    "total_consumption_bytes": 604752870113,
    "total_consumption": "563.22 GB"
  },
  "system": {
    "cpu_percent": 0,
    "cpu_cores": 1,
    "ram_used_gb": 0.41,
    "ram_total_gb": 1.03,
    "ram_percent": 40,
    "disk_used_gb": 3.7,
    "disk_total_gb": 19.6,
    "disk_percent": 19.1,
    "net_rx": "0 B/s",
    "net_tx": "0 B/s"
  }
}
```

`total_consumption_bytes` is the exact numeric value; `total_consumption` is formatted for display. Network values are current receive and transmit speeds.

## Ping panel

Pings the panel to verify connectivity, measure latency, validate authentication, and retrieve the current server timestamp.

```bash
curl 'https://your-domain.example/api/v1/ping' \
  -H 'X-API-Key: sk-your-key'
```

Example response:

```json
{
  "success": true,
  "message": "pong",
  "timestamp": 1726660000,
  "server_time": "2026-09-18 13:42:00"
}
```

## Create a user

```bash
curl -X POST 'https://your-domain.example/api/v1/users' \
  -H 'X-API-Key: sk-your-key' \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"strong-password","duration_days":30,"max_traffic_gb":100,"max_devices":3,"note":"Team A"}'
```

The response includes the new user and password so an integration can deliver credentials. Passwords are never returned by list/get. The `portal_url` always uses the public `/sub` path and never includes the panel secret path.

Example response:

```json
{
  "success": true,
  "user": {
    "id": 12,
    "username": "alice",
    "password": "strong-password",
    "is_active": true,
    "max_traffic_gb": 100,
    "used_traffic_bytes": 0,
    "expire_date": "2026-10-14 12:30:00",
    "max_devices": 3,
    "note": "Team A",
    "portal_url": "https://your-domain.example/sub?u=alice"
  }
}
```

## List and get users

```bash
curl 'https://your-domain.example/api/v1/users?q=alice&page=1&per_page=25' \
  -H 'X-API-Key: sk-your-key'

curl 'https://your-domain.example/api/v1/users/12' \
  -H 'X-API-Key: sk-your-key'
```

Search by username with the `q` parameter:

```bash
curl 'https://your-domain.example/api/v1/users?q=mehran' \
  -H 'X-API-Key: sk-your-key'
```

Example list response:

```json
{
  "success": true,
  "users": [
    {
      "id": 12,
      "username": "alice",
      "is_active": true,
      "max_traffic_gb": 100,
      "used_traffic_bytes": 5242880,
      "expire_date": "2026-10-14 12:30:00",
      "max_devices": 3,
      "note": "Team A",
      "portal_url": "https://your-domain.example/sub?u=alice"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 25,
    "total_items": 1,
    "total_pages": 1
  }
}
```

## Edit a user

```bash
curl -X PATCH 'https://your-domain.example/api/v1/users/12' \
  -H 'X-API-Key: sk-your-key' -H 'Content-Type: application/json' \
  -d '{"duration_days":60,"max_traffic_gb":200,"max_devices":4,"note":"Renewed"}'
```

Supported fields: `password`, `duration_days`, `max_traffic_gb`, `max_devices`, `note`, and `is_active`. `duration_days: 0` means lifetime, `max_traffic_gb: 0` means unlimited, and devices are limited to 1–10. Usernames cannot be changed; create a new account instead.

## Change password

```bash
curl -X POST 'https://your-domain.example/api/v1/users/12/password' \
  -H 'X-API-Key: sk-your-key' -H 'Content-Type: application/json' \
  -d '{"password":"new-password"}'
```

## Enable or disable a user

```bash
curl -X POST 'https://your-domain.example/api/v1/users/12/status' \
  -H 'X-API-Key: sk-your-key' -H 'Content-Type: application/json' \
  -d '{"is_active":false}'
```

Disabling a user also disconnects active sessions.

Example status response:

```json
{
  "success": true,
  "user": {
    "id": 12,
    "username": "alice",
    "is_active": false
  }
}
```

## Reset user traffic

Resets consumed traffic volume (`used_traffic_bytes`) for a specified user back to 0:

```bash
curl -X POST 'https://your-domain.example/api/v1/users/12/reset-traffic' \
  -H 'X-API-Key: sk-your-key'
```

Example response:

```json
{
  "success": true,
  "message": "Traffic usage for user 'alice' has been reset to 0.",
  "user": {
    "id": 12,
    "username": "alice",
    "is_active": true,
    "max_traffic_gb": 100,
    "used_traffic_bytes": 0,
    "expire_date": "2026-10-14 12:30:00",
    "max_devices": 3,
    "note": "Team A",
    "portal_url": "https://your-domain.example/sub?u=alice"
  }
}
```

## Delete

```bash
curl -X DELETE 'https://your-domain.example/api/v1/users/12' \
  -H 'X-API-Key: sk-your-key'
```

## Backup users

Downloads the same users-only SQLite backup file available from Settings → Database Backup & Restore. It includes user accounts, credentials, traffic quotas, expiration dates, and the backup metadata table.

```bash
curl -OJ 'https://your-domain.example/api/v1/backup/users' \
  -H 'X-API-Key: sk-your-key'
```

## Restore users

Restores VPN user accounts from an SQLite database backup file (`.db`, `.sqlite`, or `.sqlite3`). Validates file signature, database integrity, and schema structure before atomically applying changes, syncing IPsec secrets, and terminating outdated sessions. Send the database file as `multipart/form-data` with field name `backup_file` or `file`.

```bash
curl -X POST 'https://your-domain.example/api/v1/restore/users' \
  -H 'X-API-Key: sk-your-key' \
  -F 'backup_file=@ike_users_backup.db'
```

Example response:

```json
{
  "success": true,
  "message": "Successfully restored 15 users!",
  "restored_count": 15
}
```

## System updates

### Check for updates

Checks GitHub for new official stable releases. Uses a 6-hour cache by default to prevent API rate limits. Pass `force=true` or `force=1` to force a real-time check.

```bash
curl 'https://your-domain.example/api/v1/system/update/check?force=true' \
  -H 'X-API-Key: sk-your-key'
```

Example response:

```json
{
  "success": true,
  "cached": false,
  "current_version": "1.9.3",
  "latest_version": "1.9.4",
  "current_commit": "4928a96",
  "latest_commit": "c3d2e1a",
  "update_available": true,
  "is_newer_commit": true,
  "release_name": "IKE-UI v1.9.4 Release",
  "release_notes": "Official stable release notes and fixes.",
  "html_url": "https://github.com/mehranpng/IKE-UI/releases/tag/v1.9.4",
  "last_checked": 1726930000
}
```

### Trigger update

Launches the automated update to the latest official stable release in a detached background worker. Active VPN client connections will NOT be disconnected.

```bash
curl -X POST 'https://your-domain.example/api/v1/system/update' \
  -H 'X-API-Key: sk-your-key'
```

Example response (HTTP 202 Accepted):

```json
{
  "success": true,
  "message": "Stable update process initiated in background.",
  "current_version": "1.9.3",
  "target_version": "1.9.4",
  "target_commit": "c3d2e1a"
}
```

## Responses and status codes

Every successful response contains `success: true`. Errors contain `success: false` and an `error` message. Common status codes: `201` created, `400` invalid input, `401` invalid key, `404` not found, and `409` duplicate username.

Example error response:

```json
{
  "success": false,
  "error": "A valid API key is required."
}
```
