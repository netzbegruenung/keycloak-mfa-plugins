# Keycloak YubiKey OTP 2FA Authenticator

Keycloak Authentication Provider implementation that lets a user use a physical
YubiKey as a second factor by typing the 44-character YubiKey OTP string (the
long string the key "types" when touched). Validation is done against Yubico's
validation API (Validation Protocol v2.0), either the cloud endpoint
`https://api.yubico.com/wsapi/2.0/verify` or a self-hosted validation server.

This is the classic Yubico OTP protocol, not WebAuthn/FIDO2/U2F.

# Installing
1. `mvn clean install` from the repo root.
2. Copy `yubikey-authenticator/target/netzbegruenung.yubikey-authenticator-v26.6.5.jar`
   into the `providers` directory of your Keycloak:
   ```shell
   cp netzbegruenung.yubikey-authenticator-v26.6.5.jar /path/to/keycloak/providers
   ```
3. Run the `build` command and restart Keycloak:
   ```shell
   /path/to/keycloak/bin/kc.sh build [your-additional-flags]
   systemctl restart keycloak.service
   ```

# Setup
1. Get a Client ID + Secret Key from https://upgrade.yubico.com/getapikey/ (or
   from your self-hosted validation server).
2. Navigate to your Authentication flow configuration:
   `https://keycloak.example.com/admin/master/console/#/YOUR-REALM/authentication`.
   Edit the `Browser flow` and add a new execution / 2FA Step
   Add **"YubiKey Authentication (2FA)"** (last page of the executions) above or below OTP Form / WebAuthn. Set it to
   `Alternative`.
3. Open that execution's config. **You must set the config Alias to exactly
   `yubikey-2fa`** — this is required so that the enrollment (Required Action)
   step can find the Client ID / Secret Key / API URL, since it runs outside
   the authenticator execution and has no direct handle to its config.
   Fill in **Yubico Client ID**, **Yubico Secret Key**, and optionally override
   **Yubico API URL** for a self-hosted server.
4. Go to Authentication > Required Actions and make sure **"Set up YubiKey"**
   is enabled.

# Usage
Users can enroll/remove a YubiKey in the account console at
`/realms/<realm>/account/#/account-security/signing-in` → "YubiKey" → touch
the key to register it; use "Remove" to delete it.

At login, when prompted, touch the YubiKey to submit the OTP.
