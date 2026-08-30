# mb-print-cloud

Standalone cloud print broker for `mb-printer`. It runs as one binary with an
owner-only TOML config and an automatically managed SQLite database.

```sh
cargo run -- init --config ./mb-print-cloud.toml
cargo run -- serve --config ./mb-print-cloud.toml
```

`init` prints the tenant ID and API bearer token once. The generated defaults
listen on loopback (`9850` for HTTPS/JSON behind a proxy and `9851` for gRPC).
For production, expose both listeners through a TLS reverse proxy and update
`public_api_url` and `public_agent_url` to their HTTPS URLs.

The service has no dependency on `mb-control-plane`, Odoo, or another product
backend. Host applications call its tenant-scoped JSON API using the generated
credential. Agents authenticate with credentials issued by the enrollment API.

The OpenAPI 3.1 document is served at `/openapi.json`. See
[`docs/operations.md`](docs/operations.md) for Caddy, enrollment, revocation,
backup, and ambiguous-output procedures.

The contract is generated from the Axum handlers and Rust wire types with
`utoipa`/`utoipa-axum`; it is not hand-maintained JSON. Export the exact
contract for a client build with `mb-print-cloud openapi`.
