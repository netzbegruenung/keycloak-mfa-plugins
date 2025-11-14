# MFA Dev Runner

This module is a development utility designed to streamline the development of the Keycloak MFA plugins. It does not contain any source code itself. Instead, it provides a pre-configured environment to run a Keycloak server with all the MFA plugins from this repository already deployed.

## Overview

The `mfa-dev-runner` module leverages the Keycloak Quarkus extension (`keycloak-quarkus-server`) to run Keycloak as a Quarkus application in development mode.

Its `pom.xml` is configured to:
1.  Include the `sms-authenticator`, `app-authenticator`, and `enforce-mfa` modules as dependencies.
2.  Include the `keycloak-quarkus-server` dependency.
3.  Configure the `quarkus-maven-plugin` to launch the Keycloak server.

This setup allows you to work on the MFA plugins with the benefits of hot-reloading and easy debugging, without needing to manually build and deploy the plugin JARs.

## Usage

To start the Keycloak server with all the MFA plugins, run the following command from the root of the repository:

```bash
mvn -f mfa-dev-runner/pom.xml compile quarkus:dev
```

This will launch a Keycloak instance with the authenticators from the other modules readily available for use and testing.

## Benefits

-   **Hot Reload:** Any changes you make to the source code of the MFA plugins will be automatically detected, and the application will be reloaded.
-   **Step Debugging:** You can attach a Java debugger to the running Quarkus process to debug your authenticators.
-   **Simplified Workflow:** There is no need to manually build the `.jar` files for the extensions and copy them into a `providers` folder. The development server handles this automatically.

## Configuration

The `pom.xml` in this module contains the configuration for the `quarkus-maven-plugin`. The arguments for starting the Keycloak development server are configured within the `<argsString>` tag, which includes settings for the database connection.

For more details on how Keycloak runs as a Quarkus extension, you can refer to the [Keycloak developer documentation](https://github.com/keycloak/keycloak/blob/main/quarkus/CONTRIBUTING.md).

