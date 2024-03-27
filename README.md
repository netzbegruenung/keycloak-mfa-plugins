# Keycloak MFA Plugin collection

This repository contains the source code for a collection of Keycloak MFA plugins. The plugins are:
* SMS authenticator (production ready)
* Force MFA & Selection dialog (work in progress)
* Native App MFA integration (work in progress)

The different plugins are documented in the submodules README or in docs folder.

# License
The code of this project is Apache 2.0 licensed. Parts of the original code are MIT licensed.

# Building

1. Clone this repository
1. Install Apache Maven
1. Change into the cloned directory and run
   ```shell
   mvn clean install
   ```
   A file `target/netzbegruenung.keycloak-2fa-sms-authenticator.jar` should be created.

If building fails and the problem is caused or related to the dev module or tests, try to run `mvn clean install -DskipTests`.

## Deployment
Deployment is done by github actions: `.github/workflows/release.yml`
To trigger the release workflow be sure to have proper access rights and follow the steps below.
https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/configuring-tag-protection-rules#about-tag-protection-rules

1. Update revision property in parent POM file `pom.xml`
1. `git tag -a v1.2.3 -m "Bump version 1.2.3"`
1. `git push --tags`

After building completes the new release is available on github containing the jar files for each module.
