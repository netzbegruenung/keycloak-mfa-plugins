# Keycloak 2FA SMS Authenticator

Keycloak Authentication Provider implementation to get a 2nd-factor authentication with a OTP/code/token send via SMS with a configurable HTTPS API.
It should be possible to interact with most SMS providers. Issues and pull requests to support more SMS providers are welcome.

This is a fork of a great demo implementation by [@dasniko](https://github.com/dasniko/keycloak-2fa-sms-authenticator), and also takes huge chunks of code
from the original authenticator provider [documentation](https://www.keycloak.org/docs/latest/server_development/index.html#_auth_spi) and [example](https://github.com/keycloak/keycloak/tree/main/examples/providers/authenticator) from Keycloak itself.

# Installing

1. Go to https://github.com/netzbegruenung/keycloak-mfa-plugins/releases and download the latest `.jar` file.
1. Copy the jar into Keycloak’s `providers` directory:
   ```shell
   cp netzbegruenung.keycloak-2fa-sms-authenticator.jar /path/to/keycloak/providers
   ```
1. Run `build` and restart Keycloak:
   ```shell
   /path/to/keycloak/bin/kc.sh build [your-additional-flags]
   systemctl restart keycloak.service
   ```

# Setup

1. **Authentication → Required actions**: enable **Phone Validation** and **Update Mobile Number**.
1. **Authentication → Flows** (e.g. **Browser**): add **SMS Authentication (2FA)** next to OTP, usually as **Alternative**.
1. **Configure SMS** (same fields in both places below; labels match the admin UI):

   **Default (new installs)** — open **Update Mobile Number** → **Settings** (gear) and set your provider (API URL, secrets, code length, TTL, etc.). This covers **registering a phone number** (required actions) and, unless you override it below, **login** SMS as well.

   **Legacy (upgrades)** — if you already configured SMS on the Browser flow step with alias **`sms-2fa`**, you can keep that: leave **SMS API URL** and **Simulation mode** empty on *Update Mobile Number* and the plugin still reads the realm config named `sms-2fa` for registration. New projects should use the required-action settings instead.

   **Login-only override (optional)** — if one flow needs different SMS settings than registration, attach a config to the **SMS Authentication (2FA)** execution in that flow; those values apply only at login and override the shared base for keys you set there.

# Provider configuration options

Requests are sent as HTTP POST by default (or GET if you set **SMS API GET URL template**). Match your provider’s API using:

1. **SMS API URL**: URL for the POST request.
1. **URL encode data**: off = JSON body; on = URL-encoded parameters.
1. **Put API Secret Token in Authorization Header**: if set, secret goes in `Authorization`; token attribute and Basic Auth username are ignored.
1. **API Secret Token Attribute (optional)**: JSON field name for the token (leave empty if the secret is only in the URL path).
1. **API Secret (optional)**: secret value, or Basic Auth password if a username is set.
1. **Basic Auth Username (optional)**: enable Basic Auth when required.
1. **Message Attribute**: field for SMS text (e.g. `text`).
1. **Receiver Phone Number Attribute**: field for the destination number (e.g. `to`).
1. **Sender Phone Number Attribute**: field for sender number; optional.
1. **SenderId**: value sent in the sender field.
1. **Use message UUID** / **UUID attribute**: generate and send a UUID when the API requires it.
1. **Request JSON template**: custom body with `%s` placeholders (UUID if enabled, then phone, then message).

Other useful fields: **Simulation mode**, **Code length**, **Time-to-live**, **Default country prefix**, **Force 2FA**, **Format phone number**, etc. (see the admin UI on the required action or authenticator config).

# Usage

After configuration, users set up SMS in the account console, e.g.  
`/realms/<realm>/account/#/account-security/signing-in` — enter and confirm their mobile number.

# Enforce SMS 2FA

If **Force 2FA** is enabled in your SMS configuration (required action or legacy `sms-2fa` config) and the user has no other second factor yet, they are prompted to set up SMS (or another allowed method).
