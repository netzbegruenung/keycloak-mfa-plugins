# Keycloak MFA Plugin collection

This repository contains the source code for a collection of Keycloak MFA plugins. The plugins are:
* [SMS authenticator](sms-authenticator/README.md): Provides SMS as authentication step. SMS are sent via HTTP API, which can be configured. (production ready)
* [Email authenticator](email-authenticator/README.md): Provides Email OTP as authentication step. Uses the SMTP server configured in the realm. (production ready)
* [Enforce MFA](enforce-mfa/README.md): Force users to configure a second factor after logging in. (beta)
* [Native App MFA integration](app-authenticator/README.md): connect a mobile app to Keycloak which receives a notification about a pending login process and allows the user to allow/block the login request. (work in progress)
* [Trusted Device authenticator](trusted-device-authenticator/README.md): remember a device after a successful 2FA login and skip the second factor on it for a configurable period.

The different plugins are documented in the submodules README. If you need support for deployment or adjustments, please contact [support@verdigado.com](mailto:support@verdigado.com).

## License
The code of this project is Apache 2.0 licensed. Parts of the original code are MIT licensed.

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
Deployment is done by github actions: `.github/workflows/release.yml`
To trigger the release workflow be sure to have proper access rights and follow the steps below.
https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/configuring-tag-protection-rules#about-tag-protection-rules

### Versioning
Versions follow `<keycloak.version>-<counter>`, e.g. `26.7.0-0`, rather than independent semantic versioning. The counter starts at `0` for the first release built against a given Keycloak version and increments for any additional release against that same Keycloak version (e.g. a hotfix); it resets to `0` whenever `keycloak.version` is bumped in `pom.xml`.

Run the block below to bump the version, commit, and tag (in IntelliJ you can run it directly from this file):
```shell
set -e
KEYCLOAK_VERSION=$(mvn help:evaluate -Dexpression=keycloak.version -q -DforceStdout \
  | awk '{gsub(/\x1b\[[0-9;]*[mK]/,""); print}' \
  | tr -d '\r')
LAST_COUNTER=$(git tag -l "v${KEYCLOAK_VERSION}-*" \
  | sed "s/^v${KEYCLOAK_VERSION}-//" \
  | sort -n | tail -1)
NEW_VERSION="${KEYCLOAK_VERSION}-$(( ${LAST_COUNTER:--1} + 1 ))"
mvn versions:set -DnewVersion="$NEW_VERSION"
mvn versions:commit
git add -u
git commit -m "chore: release $NEW_VERSION"
git tag -a "v$NEW_VERSION" -m "Release $NEW_VERSION"
echo "Tagged v$NEW_VERSION - review it, then push with: git push --follow-tags"
```

Review the resulting commit and tag, then trigger the release by pushing both together:
```shell
git push --follow-tags
```
(`--follow-tags` pushes the commit and the new annotated tag in one step; a plain `git push` would not push the tag on its own, and it's the tag push that triggers the workflow.)

After building completes the new release is available on github containing the jar files for each module. Release notes are auto-generated from merged PRs since the last tag (`gh release create --generate-notes` in the workflow), so any PR description explaining a notable change — like this versioning switch — is automatically surfaced to the community.
