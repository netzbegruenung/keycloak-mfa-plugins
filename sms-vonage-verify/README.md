# Vonage Verify for the Keycloak 2FA SMS Authenticator

A verification provider for the [SMS authenticator](../sms-authenticator/README.md) that uses the [Vonage Verify v2 API](https://developer.vonage.com/en/verify/overview). Vonage generates the code, sends it by SMS, and decides if the code the user entered is correct. Keycloak never sees the code.

This is different from sending the code with the Vonage SMS or Messages API, which works with the `generic` provider of the SMS authenticator and does not need this module.

# Installing
1. Install the SMS authenticator as described in its [README](../sms-authenticator/README.md). This module does not work without it.
1. Copy the jar of this module into the `providers` directory of your Keycloak as well:
   ```shell
   cp netzbegruenung.sms-vonage-verify-v*.jar /path/to/keycloak/providers
   ```
1. Run the `build` command and restart Keycloak.

# Setup
Set up the SMS authenticator, then change these options in the config of the `sms-2fa` execution:
1. `SMS verification provider`: `vonage-verify`.
1. `Vonage Verify: API key` and `Vonage Verify: API secret`: the credentials of your Vonage account.
1. `Vonage Verify: Brand`: the name of your company or service, which is part of the SMS text. At most 18 characters.
1. `Vonage Verify: Locale (optional)`: a [Vonage locale](https://developer.vonage.com/en/verify/guides/verify-v2-languages) like `en-us` to use for all users. If empty, the locale of the user in Keycloak is used when Vonage has an SMS text for it. Otherwise no locale is sent, and Vonage chooses the language from the country of the phone number.
1. `Vonage Verify: Template ID (optional)`: the id of a [custom template](https://developer.vonage.com/en/verify/guides/custom-templates) for the SMS text.
1. `Vonage Verify: API URL`: only change this for testing.

These options of the SMS authenticator are also used:
1. `Code length`: has to be between 4 and 10.
1. `Time-to-live`: sent to Vonage as `channel_timeout`, the time until the SMS step of the verification times out. Vonage accepts 15 to 900 seconds, other values are changed to the nearest of the two. On the Verify Success pricing model Vonage does not accept less than 60 seconds.
1. `Default country prefix`: used to convert phone numbers to the international format, as for the `generic` provider.

The settings of the `generic` provider (`SMS API URL`, `Simulation mode`, ...) are not used. This includes the SMS text of the Keycloak theme (`smsAuthText`): the text is the default text of Vonage, or your custom template.

# How it works
- When the code form is shown, a verification with a single SMS step is started (`POST /v2/verify`). The id of the request is kept in the authentication session.
- When the user submits a code, Vonage is asked if it is correct (`POST /v2/verify/{request_id}`).
- Vonage does not allow two open verifications for the same phone number. If the code form is shown again while a request is open (e.g. a page refresh), no new request is started and the user keeps using the code of the first SMS. A user that starts a new login in another browser while a request is open gets an error until the request has timed out, see `Time-to-live`.
- Vonage ends a verification after three wrong codes. The user then sees the "code has expired" error and has to log in again to get a new code.

# Testing
The tests are run with `mvn test` from the repo root (this module needs `sms-authenticator` in the same build). They do not call Vonage: the unit tests (`VonageVerifyClientTest`) and the integration tests (`VonageVerifyFlowTest`) run against a stub that answers like the Verify v2 API specification says.
