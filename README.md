# Keycloak MFA Plugin collection (B-Sharpe fork)

> **This is a fork** of [netzbegruenung/keycloak-mfa-plugins](https://github.com/netzbegruenung/keycloak-mfa-plugins),
> maintained by [B-Sharpe](https://github.com/b-sharpe-SA). It starts from upstream tag
> [`v26.8.0-1`](https://github.com/netzbegruenung/keycloak-mfa-plugins/releases/tag/v26.8.0-1) and adds community pull
> requests upstream has not merged yet, plus fraud protection for the SMS step of user registration.
>
> It is a drop-in replacement: provider IDs, the `sms-2fa` configuration alias, the credential type, the templates and
> the Java packages are unchanged, so an existing realm configuration keeps working.

## What this fork adds

### Upstream pull requests integrated

| PR | Change |
|---|---|
| [#469](https://github.com/netzbegruenung/keycloak-mfa-plugins/pull/469) | Keycloak 26.8.1 |
| [#471](https://github.com/netzbegruenung/keycloak-mfa-plugins/pull/471) | libphonenumber 9.0.42 |
| [#474](https://github.com/netzbegruenung/keycloak-mfa-plugins/pull/474) | `mobileNumberAttribute` respected for storage and uniqueness checks |
| [#451](https://github.com/netzbegruenung/keycloak-mfa-plugins/pull/451) | Formatting characters stripped from phone numbers before sending |
| [#439](https://github.com/netzbegruenung/keycloak-mfa-plugins/pull/439) | Phone number masked on the login page (last 4 digits shown) |
| [#400](https://github.com/netzbegruenung/keycloak-mfa-plugins/pull/400) | SMS gateway credentials can be Keycloak vault references |
| [#444](https://github.com/netzbegruenung/keycloak-mfa-plugins/pull/444) | Code kept across re-sends, resend button, cooldown and rate limit |
| [#429](https://github.com/netzbegruenung/keycloak-mfa-plugins/pull/429) | "Change phone number" button on the enrolment code step |
| [#443](https://github.com/netzbegruenung/keycloak-mfa-plugins/pull/443) | Phone attribute as source of truth; brute-force lockout for wrong SMS and email codes |
| [#397](https://github.com/netzbegruenung/keycloak-mfa-plugins/pull/397) | Allowed regions for SMS phone numbers (`allowedRegions`) |

From #397 only the region allowlist is kept: its brute-force part overlaps #443, whose version is used.

### Changes of our own (sms-authenticator)

- Phone numbers are masked in logs (`+*****4567`). In GET mode, the request URL, which carries the number and the
  message with the code, is no longer written to error logs.
- 100 % branch coverage of the module, measured both in the tests and in the Keycloak server they start; the build
  fails below it.
- CI runs the whole test suite on every push and pull request and publishes the coverage report as an artifact.

### In progress: fraud protection at registration

Controls on the phone-number step of registration against SMS pumping (bots creating accounts to trigger paid SMS):
number-change lock and resend cooldown, Cloudflare Turnstile on number change, a send cap, a wrong-code account lock,
a number-type check through a configurable URL, and a silent block for fraudulent accounts. They will be documented in
the [SMS authenticator README](sms-authenticator/README.md) when released.

## Upstream, issues and support

Upstream is [netzbegruenung/keycloak-mfa-plugins](https://github.com/netzbegruenung/keycloak-mfa-plugins), developed
by Netzbegrünung e.V. and verdigado eG. Issues about this fork go to
[this repository](https://github.com/b-sharpe-SA/keycloak-mfa-plugins/issues). Changes useful upstream are offered back
as pull requests.

# Upstream documentation

The sections below come from upstream. The support contact refers to the upstream project.

This repository contains the source code for a collection of Keycloak MFA plugins. The plugins are:
* [SMS authenticator](sms-authenticator/README.md): Provides SMS as authentication step. SMS are sent via HTTP API, which can be configured. (production ready)
* [Email authenticator](email-authenticator/README.md): Provides Email OTP as authentication step. Uses the SMTP server configured in the realm. (production ready)
* [Enforce MFA](enforce-mfa/README.md): Force users to configure a second factor after logging in. (beta)
* [Native App MFA integration](app-authenticator/README.md): connect a mobile app to Keycloak which receives a notification about a pending login process and allows the user to allow/block the login request. (work in progress)
* [Trusted Device authenticator](trusted-device-authenticator/README.md): remember a device after a successful 2FA login and skip the second factor on it for a configurable period.

The different plugins are documented in the submodules README. If you need support for deployment or adjustments, please contact [support@verdigado.com](mailto:support@verdigado.com).

## License
The code of this project is Apache 2.0 licensed. Parts of the original code are MIT licensed.

This fork keeps the same licenses. Upstream files changed by the fork carry a "Modified by B-Sharpe" line in their
header.

## Development
[Quarkus Dev Server](mfa-dev-runner/README.md)

## Building

1. Clone this repository
1. Install Apache Maven
1. Change into the cloned directory and run
   ```shell
   mvn clean install
   ```
   A file `target/netzbegruenung.keycloak-2fa-sms-authenticator.jar` should be created.

## Releases
Releases are built by GitHub Actions (`.github/workflows/release.yml`) when a `v*` tag is pushed: the tests run on JDK
21 and 25, the jars are packaged, and a GitHub release is created with the jars and their SHA-512 hashes.

### Versioning
**Fork:** the version is not written in the poms, it comes from the tag. Tags follow
`v<keycloak.version>.<counter>`, e.g. `v26.8.2.0`: the Keycloak version the plugins are built against, then a counter
that starts at `0` and resets when `keycloak.version` changes. The dot keeps them apart from upstream's
`v<keycloak.version>-<counter>` tags. The CI passes the tag's version to Maven (`-Drevision=26.8.2.0`), which names the
jars, e.g. `netzbegruenung.sms-authenticator-v26.8.2.0.jar`; local builds are versioned `0-SNAPSHOT`.

To release, tag a commit of `main` and push the tag:
```shell
git tag -a v26.8.2.0 -m "Release 26.8.2.0"
git push origin v26.8.2.0
```

Release notes are generated from the pull requests merged since the last tag (`gh release create --generate-notes`).
