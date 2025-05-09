# Keycloak MFA Plugin collection

This repository contains the source code for a collection of Keycloak MFA plugins. The plugins are:
* [SMS authenticator](sms-authenticator/README.md): Provides SMS as authentication step. SMS are sent via HTTP API, which can be configured. (production ready)
* [Enforce MFA](enforce-mfa/README.md): Force users to configure a second factor after logging in. (beta)
* [Native App MFA integration](app-authenticator/README.md): connect a mobile app to Keycloak which receives a notification about a pending login process and allows the user to allow/block the login request. (work in progress)

The different plugins are documented in the submodules README. If you need support for deployment or adjustments, please contact [support@verdigado.com](mailto:support@verdigado.com).

## License
The code of this project is Apache 2.0 licensed. Parts of the original code are MIT licensed.

## Development
Run the Quarkus distribution in development mode for live reloading and debugging similar to: https://github.com/keycloak/keycloak/tree/main/quarkus#contributing

```shell
mvn -f some_module/pom.xml compile quarkus:dev
```

Works great:)
https://github.com/keycloak/keycloak/discussions/11841

If problems occur, check that quarkus-maven-plugin is in sync with keycloaks quarkus version.
Maven does not support builtin import of properties beside inheritance.

## Building

1. Clone this repository
1. Install Apache Maven
1. Change into the cloned directory and run
   ```shell
   mvn clean install
   ```
   A file `target/netzbegruenung.keycloak-2fa-sms-authenticator.jar` should be created.

If building fails and the problem is caused or related to the dev module or tests, try to run `mvn clean install -DskipTests`.

## Releases
Deployment is done by github actions: `.github/workflows/release.yml`
To trigger the release workflow be sure to have proper access rights and follow the steps below.
https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/configuring-tag-protection-rules#about-tag-protection-rules

1. Update project and submodules version `mvn versions:set -DnewVersion=1.2.3; mvn versions:commit`
1. Commit your changes
1. Add tag to your commit (removes all ANSI escape codes from maven output)
```shell
VERSION=$(mvn help:evaluate -Dexpression=project.version -q -DforceStdout \
  | awk '{gsub(/\x1b\[[0-9;]*[mK]/,""); print}' \
  | tr -d '\r')
git tag -a "v$VERSION" -m "Bump version $VERSION"
```
1. Trigger the release by `git push --tags`

After building completes the new release is available on github containing the jar files for each module.
