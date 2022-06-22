# Keycloak 2FA E-Mail Authenticator

Keycloak Authentication Provider implementation to get a 2nd-factor authentication with a OTP/code/token send via E-Mail.

If you intend to use this plugin, read the following paragraph carefully:

This plugin provides a second factor via e-mail. This is considered to be a fall back mechanism. We recommend to set the Verify Profile action for all new users to ensure an e-mail exists. If no e-mail is set in the user profile, this plugin will skip the second authentication step and then proceed to the configured Profile Vverification action, which includes entering an e-mail. As soon as TOTP or Webauthn is configured, the e-mail verification will be disabled.

This work is based on https://github.com/dasniko/keycloak-2fa-sms-authenticator and https://gitlab.com/niroj.adhikary/keycloak-email-otp/.
