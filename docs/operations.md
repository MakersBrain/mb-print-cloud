# Operations

## Initial setup

Create the owner-only config and SQLite file location:

```sh
mb-print-cloud init --config /etc/mb-print-cloud.toml \
  --database /var/lib/mb-print-cloud/cloud.sqlite3
```

The command prints the tenant ID and API token once. Store the token in the
calling application's secret store. The config contains only its SHA-256 hash.

Run the service as an unprivileged dedicated user:

```sh
mb-print-cloud serve --config /etc/mb-print-cloud.toml
```

The service intentionally exposes separate loopback listeners for JSON and
gRPC. A minimal Caddy deployment can publish them on separate HTTPS names:

```caddyfile
print.example.com {
    reverse_proxy 127.0.0.1:9850
}

agent.print.example.com {
    reverse_proxy h2c://127.0.0.1:9851
}
```

Set `public_api_url` and `public_agent_url` to those HTTPS origins. Keep the
gRPC proxy idle timeout longer than the 15-second heartbeat interval.

## Enrollment

Call `POST /v1/tenants/{tenant}/printer-enrollments` with the management bearer
token. Enter the returned one-time code through stdin when prompted:

```sh
mb-printer cloud enroll --server https://print.example.com
mb-printer cloud publish --connection packing-desk --name "Packing desk"
mb-printer cloud connect
```

Codes expire after ten minutes and are consumed atomically. The local agent
token and config must remain owner-only.

## Revocation

Call `POST /v1/tenants/{tenant}/printer-agents/{agent}/revoke`. The active
stream closes on its next broker check, its token stops authenticating, and its
printers become disabled and offline. Re-enrollment creates a new agent; it
does not revive the revoked identity.

## Backup and restart

Stop the single service process, copy the SQLite database and config, then
restart it. WAL mode is enabled, but copying only the main database while the
service is running is not a valid backup. On every startup all printers begin
offline until their agent reconnects.

Stored terminal jobs survive restart. Payload bytes are removed after seven
days while terminal metadata remains. Back up the local agent's
`cloud-jobs.json` alongside its config if moving that agent to another host.

## Ambiguous output and reprints

`outcome-unknown` means a printer write may have happened but completion cannot
be proven. Inspect the physical printer before submitting another job. A
reprint always uses a new idempotency key and creates a new job; never edit or
requeue the ambiguous row in SQLite.

The broker never automatically changes a job's agent or printer. Do not modify
the database to force delivery to a replacement agent.
