# Keycloak 2FA SMS Authenticator

Keycloak Authentication Provider implementation to get a 2nd-factor authentication with a OTP/code/token send via SMS with a configurable HTTPS API.
It should be possible to interact with most SMS providers. Issues and pull requests to support more SMS providers are welcome.

This is a fork of a great demo implementation by [@dasniko](https://github.com/dasniko/keycloak-2fa-sms-authenticator), and also takes huge chunks of code
from the original authenticator provider [documentation](https://www.keycloak.org/docs/latest/server_development/index.html#_auth_spi) and [example](https://github.com/keycloak/keycloak/tree/main/examples/providers/authenticator) from Keycloak itself.

# Installing
1. Go to https://github.com/netzbegruenung/keycloak-mfa-plugins/releases and download
   the latest .jar file.
1. Copy the created jar file into the `providers` directory of your Keycloak:
   ```shell
   cp netzbegruenung.keycloak-2fa-sms-authenticator.jar /path/to/keycloak/providers
   ```
1. Run the `build` command and restart Keycloak:
   ```shell
   /path/to/keycloak/bin/kc.sh build [your-additional-flags]
   systemctl restart keycloak.service
   ```

# Setup
1. Add a new execution to the 2FA flow of your Browser flow, choose "SMS Authentication (2FA)".
1. Make sure that you name it "sms-2fa". This is currently a hack that will hopefully be fixed. Additional executions with other names can be added. But this first execution will be used for the confirmation SMS when setting up a new phone number.
1. Go into the config of the execution and configure the plugin so that it works with the API of your SMS proivder.
1. Go to `/admin/master/console/#/realm/authentication/required-actions` and enable required actions "Phone Validation" and "Update Mobile Number"

# Usage
After successfully configured the authenticator and the required actions users can set up SMS Authentication in the
account console `/realms/realm/account/#/account-security/signing-in` by entering and confirming their phone number.

# Enforce SMS 2FA
If the option `Force 2FA` in the SMS Authenticator config is enabled and a user has no other 2FA method already enabled,
users will have to set up the SMS Authenticator.
