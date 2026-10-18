# bestbank
![screenshot](img/screenshot.png)

A small [Rocket](https://rocket.rs) 0.5 web app in [Rust](https://www.rust-lang.org)
that demonstrates:

- Login / logout with an **encrypted, authenticated session cookie** (Rocket
  private cookies, `HttpOnly`, `SameSite=Strict`) and Argon2id password hashes.
- Request guards, request ranking, managed state and flash messages.
- SQLite persistence via [`sqlx`](https://github.com/launchbadge/sqlx) with
  embedded migrations, with money stored as integer cents and atomic,
  overdraft-safe withdrawals.
- Handlebars templates populated from JSON endpoints.
- Authenticated, per-user WebSocket notifications (`rocket_ws`) on the same
  port as the app.

> **This is a demo, not a real bank.** It has a hard-coded demo account and no
> rate limiting. See
> [Security notes](#security-notes).

### Install Rust

Follow the [instructions](https://www.rust-lang.org/tools/install) here.

### Run the app

```
cargo run
```

Then open <http://localhost:8080>. The debug profile listens on port 8080 and
generates a throwaway secret key on each start (so sessions don't survive a
restart).

### Database

Data is stored in SQLite at `bestbank.db` in the working directory (see
`database_url` in `Rocket.toml`). Migrations in `migrations/` are compiled
into the binary and applied on startup. Delete the file to start over, or run
with a throwaway in-memory database:

```
ROCKET_DATABASE_URL=sqlite::memory: cargo run
```

### Run it behind TLS

The `release` profile listens on 8443 with TLS using the demo certificate in
`private/`. Because sessions are encrypted cookies, release mode **requires**
a secret key; Rocket refuses to start without one:

```
ROCKET_SECRET_KEY=$(openssl rand -base64 32) cargo run --release
```

Then open <https://localhost:8443>. The certificate is self-signed by the demo
CA in `private/ca_cert.pem` (generated with `private/gen_cert.sh`). Trust it or
accept the browser warning. **Never** use this certificate/key pair for
anything real.

Configuration lives in `Rocket.toml` (`[default]`, `[debug]`, `[release]`,
`[release.tls]`); any value can be overridden with `ROCKET_*` environment
variables.

### Log in / register

A demo account is seeded at startup: **admin / admin** (disable with
`seed_demo_admin = false`). New users can sign up at `/register`:

- usernames are 3-32 characters from `A-Z a-z 0-9 _ . -` and unique
  regardless of case;
- passwords must be 8-128 characters, must not be a very common password and
  must not contain the username.

Set `allow_registration = false` in `Rocket.toml` (or
`ROCKET_ALLOW_REGISTRATION=false`) to turn sign-ups off.

### Endpoints

| Method | Path                 | Auth  | Notes                                     |
|--------|----------------------|-------|-------------------------------------------|
| GET    | `/`, `/login`        | –     | Login page (with flash messages)          |
| POST   | `/login`             | –     | Form: `username`, `password`              |
| POST   | `/logout`            | –     | Clears the session                        |
| GET    | `/register`          | –     | Sign-up form                              |
| POST   | `/register`          | –     | Form: `username`, `password`, `confirm`   |
| GET    | `/user_banking`      | user  | Banking page (redirects to login if not)  |
| GET    | `/json/account_info` | user  | Balance and history, newest first         |
| POST   | `/json/deposit`      | user  | JSON `{"amount": 12.34}`                  |
| POST   | `/json/withdraw`     | user  | JSON `{"amount": 12.34}`                  |
| GET    | `/ws`                | user  | WebSocket: your own transaction events    |
| GET    | `/dump`              | admin | Users, balances, transaction counts (JSON) |
| GET    | `/static/*`          | –     | Static files (favicon)                    |

Amounts must be positive, have at most two decimal places and be at most
1,000,000.00 per transaction; withdrawals can't overdraw. Invalid requests get
a 4xx status with `{"success": false, "message": "..."}`. Unauthenticated API
requests get `401`.

### Logging

Logs are structured [`tracing`](https://docs.rs/tracing) events (Rocket's own
log output is routed through the same subscriber). Each request gets an ID,
which is returned in the `X-Request-Id` response header and included in that
request's log lines; a well-formed incoming `X-Request-Id` (e.g. from a proxy)
is reused. Logins, failed logins, logouts and transactions are logged with
structured fields.

```
RUST_LOG=debug cargo run                 # more verbose
BESTBANK_LOG_FORMAT=json cargo run       # one JSON object per line
```

### Tests

```
cargo test
cargo clippy --all-targets
```

### Security notes

What the demo does:

- Session cookies are Rocket private cookies (AES-256-GCM with the app's
  secret key), so they can't be forged or tampered with, and the user guard
  checks the user still exists.
- Passwords are stored as salted Argon2id PHC strings.
- `SameSite=Strict` on the session cookie is the CSRF defence for the POST
  routes.
- WebSocket connections require a logged-in session and only receive that
  user's events.

What it doesn't do (fine for a demo, not for production):

- The `admin`/`admin` account is hard-coded.
- No login rate limiting or account lockout.
- No CSRF tokens (relies on `SameSite`); login CSRF is not prevented.
- Sessions have no server-side revocation; logout only deletes the cookie.
