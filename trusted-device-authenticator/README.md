# Keycloak Trusted Device Authenticator

Keycloak Authentication Provider implementation that lets a user mark their browser as a trusted device after a successful second-factor login, so subsequent logins from that same browser can skip the second factor until the trust expires.

This is an independent reimplementation of the ideas from upstream Keycloak pull request [keycloak/keycloak#48138](https://github.com/keycloak/keycloak/pull/48138), rebuilt on public Keycloak SPI extension points so it can ship as a regular provider jar instead of requiring a patched Keycloak core.

# Installing
1. Go to https://github.com/netzbegruenung/keycloak-mfa-plugins/releases and download the latest `netzbegruenung.trusted-device-authenticator-*.jar`.
1. Copy the jar into the `providers` directory of your Keycloak:
   ```shell
   cp netzbegruenung.trusted-device-authenticator-*.jar /path/to/keycloak/providers
   ```
1. Run the `build` command and restart Keycloak:
   ```shell
   /path/to/keycloak/bin/kc.sh build [your-additional-flags]
   ```

# Setup
1. Go to `/admin/master/console/#/YOUR-REALM/authentication/required-actions` and enable the required action **Manage Trusted Device**.
1. Navigate to your Authentication flow configuration and duplicate the flow you want to use (e.g. `browser`), since built-in flows are read-only.
1. Inside the 2FA part of the flow, add the two steps so that the trusted-device check runs as an alternative to your existing second factor:
   1. Add `Trusted Device` and set it to `Alternative`.
   1. Add a sub-flow (also `Alternative`) that contains your existing second-factor step(s) (e.g. `OTP Form`) set to `Required`, followed by `Trusted Device Register` set to `Required`.
1. Click the **Actions** menu (three dots) next to the `Manage Trusted Device` required action and select **Config** to set:

| Parameter | Description | Default |
| --- | --- | --- |
| Trust duration (days) | Number of days the device stays trusted before the user is asked again. | `7` |

# Usage
After a user completes their normal second factor, they're asked whether to trust the current device. The device name is automatically detected (e.g. "Windows 10 / Chrome") and can be edited before confirming. If they accept, a signed cookie and a matching `netzbegruenung-trusted-device` credential are stored for the user; as long as both are present and unexpired, the `Trusted Device` step succeeds and the second-factor sub-flow is skipped on that browser. The trusted device also shows up in the account console (`/realms/realm/account/#/account-security/signing-in`) and can be revoked there like any other credential.

# License
Apache License 2.0
