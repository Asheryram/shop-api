# Customer authentication

## Goal

Enable customers to create an account and sign in to the shop website.

## Backend feature

Provide registration and authentication capabilities that `shop-web` can use to create and sign in a customer.

## Expected behavior

- Accept an account identifier and password through a documented authentication endpoint.
- Allow a customer to register with an email address and a password of at least 12 characters.
- Establish a session immediately after successful registration.
- Verify credentials against the backend's account data and establish authenticated state using the mechanism selected for this service.
- Return a documented success response that identifies the authenticated customer without exposing sensitive account data.
- Reject invalid credentials consistently without revealing whether an account exists or which credential was incorrect.
- Validate missing and malformed input and return an appropriate client error.
- Never log plaintext passwords or authentication secrets; do not return credentials in responses.
- Document the endpoint, request/response contract, and browser authentication behavior, including required CORS or cookie settings, for the frontend team.

## Acceptance criteria

- Valid credentials establish authentication and produce the documented success response.
- Valid registration creates a customer with a salted password hash and establishes authentication.
- Duplicate email addresses and weak passwords do not create a second account or a session.
- Invalid credentials do not establish authentication and return a generic authentication failure.
- Missing or malformed input is rejected; unexpected server errors do not appear as successful authentication.
- Automated tests cover successful authentication, invalid credentials, and malformed input.
- The documented contract gives `shop-web` enough information to integrate without assuming an auth mechanism.

## Coordination

The frontend owns its separate login-experience feature definition and UI. Agree on the request/response contract and browser authentication behavior before integration.

## Implemented contract

- `POST /api/auth/login` accepts `application/json` with `email` and `password`. Success is `200 {"authenticated": true, "customer": {"id": 1, "email": "customer@example.com"}}`; invalid credentials are `401 {"error": "Invalid email or password"}`. Missing or malformed input is `400`.
- `POST /api/auth/register` accepts the same JSON shape and requires a password with at least 12 characters. Success returns the same authenticated customer shape and sets the session cookie. An existing email returns `409`; invalid input returns `400`.
- Browser preflight requests for registration are supported and allow `Content-Type` from the configured `WEB_ORIGIN`.
- A successful login sets an opaque, database-backed `shop_session` cookie. It is `HttpOnly`, `Secure`, `SameSite=None`, scoped to `/`, and expires after seven days. The token is stored only as a SHA-256 digest in `customer_sessions`.
- `GET /api/auth/session` returns the same authenticated customer shape or `200 {"authenticated": false}`. `POST /api/auth/logout` revokes the current session and clears the cookie.
- Browser requests must send credentials (`credentials: "include"`). Configure `WEB_ORIGIN` to the exact HTTPS origin of the shop website (scheme and host, no path). The API returns credentialed CORS headers only for that origin and rejects auth requests from other origins. Both services must be served over HTTPS for the secure cookie to work.
- Customer passwords are stored as salted scrypt hashes. Registration is the normal account-creation path. After deployment migrations, an operator can also provision an account with `python create_customer.py customer@example.com`; the command prompts for the password without putting it in shell history. `DATABASE_URL` must target the API database.
- Auth endpoints return generic credential failures, avoid reflecting secrets, and do not log request bodies. Session responses are not cacheable.
