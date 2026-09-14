# IKE-UI User Management API

API v1 manages VPN user accounts only. It cannot read or change panel settings.

## Base URL

Use the Base URL shown in Settings → User Management API:

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
| GET | `/users` | List users. Query: `q`, `page`, `per_page`. |
| POST | `/users` | Create a user. |
| GET | `/users/{id}` | Get one user. |
| PATCH / PUT | `/users/{id}` | Edit user fields. |
| POST | `/users/{id}/password` | Change password. |
| POST | `/users/{id}/status` | Enable or disable a user. |
| DELETE | `/users/{id}` | Delete user and disconnect active sessions. |

## Create a user

```bash
curl -X POST 'https://your-domain.example/api/v1/users' \
  -H 'X-API-Key: sk-your-key' \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"strong-password","duration_days":30,"max_traffic_gb":100,"max_devices":3,"note":"Team A"}'
```

The response includes the new user and password so an integration can deliver credentials. Passwords are never returned by list/get.

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
    "portal_url": "https://faghir.seytann.com/sub?u=alice"
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
      "portal_url": "https://faghir.seytann.com/sub?u=alice"
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

## Delete

```bash
curl -X DELETE 'https://your-domain.example/api/v1/users/12' \
  -H 'X-API-Key: sk-your-key'
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
