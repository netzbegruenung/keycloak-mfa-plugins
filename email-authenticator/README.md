# Keycloak Email Authenticator

Keycloak Authentication Provider implementation that sends a one-time code (OTP) via email using the SMTP server configured in the Keycloak realm.

# Installing
1. Go to https://github.com/netzbegruenung/keycloak-mfa-plugins/releases and download the latest `netzbegruenung.email-authenticator-*.jar`.
1. Copy the jar into the `providers` directory of your Keycloak:
   ```shell
   cp netzbegruenung.email-authenticator-*.jar /path/to/keycloak/providers
   ```
1. Run the `build` command and restart Keycloak:
   ```shell
   /path/to/keycloak/bin/kc.sh build [your-additional-flags]
   systemctl restart keycloak.service
   ```

# Setup
1. Log in to the Keycloak Admin Console and select your realm.
1. Make sure the realm's **Email** settings point to a working SMTP server.
1. Go to **Authentication** in the left sidebar and select the flow you want to use (e.g., `browser`).
1. Since built-in flows are read-only, duplicate the flow if you haven't already: click the three dots in the top right of the flow details and select **Duplicate**.
1. In your new flow, click **Add step**.
1. Search for `Email Authentication (2FA)` and click **Add**.
1. Set the requirement to `Alternative` (or `Required` to enforce it).
1. Click the **Actions** menu (three dots) next to the `Email Authentication (2FA)` step and select **Config**. The following options are available:

| Parameter | Description | Default |
| --- | --- | --- |
| Code length | Number of digits of the generated OTP. | `6` |
| Time-to-live | Validity period of the OTP in seconds. | `300` |
| Force 2FA | If no other 2FA method is configured, the user is forced to verify their email and use Email OTP. | `false` |

The email subject and body are taken from the theme message bundle (keys `emailAuthSubject` and `emailAuthText`) and can be customised per realm/theme. The body supports `%1$s` (code) and `%2$d` (validity in minutes) placeholders.

# Usage
After the authenticator is wired into the flow, users with a verified email address automatically receive a login code on the second-factor step.

# Enforce Email 2FA
If the option `Force 2FA` is enabled and a user has no other 2FA method set up, Keycloak will add the built-in `VERIFY_EMAIL` required action so the user verifies their address before continuing.

# License
Apache License 2.0
