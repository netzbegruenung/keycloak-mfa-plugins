# Keycloak MFA Plugin collection

This repository contains the source code for a collection of Keycloak MFA plugins. The plugins are:
* SMS authenticator (production ready)
* Force MFA & Selection dialog (work in progress)
* Native App MFA integration (work in progress)

The different plugins are documented below.

# License
The code of this project is Apache 2.0 licensed. Parts of the original code are MIT licensed.

# Keycloak 2FA SMS Authenticator

Keycloak Authentication Provider implementation to get a 2nd-factor authentication with a OTP/code/token send via SMS with a configurable HTTPS API. It should be possible to interact with most SMS providers. Issues and pull requests to support more SMS providers are welcome.

This is a fork of a great demo implementation by [@dasniko](https://github.com/dasniko/keycloak-2fa-sms-authenticator), and also takes huge chunks of code from the original authenticator provider [documentation](https://www.keycloak.org/docs/latest/server_development/index.html#_auth_spi) and [example](https://github.com/keycloak/keycloak/tree/main/examples/providers/authenticator) from Keycloak itself.

## Building

1. Clone this repository
1. Install Apache Maven
1. Change into the cloned directory and run
   ```shell
   mvn package
   ```
   A file `target/netzbegruenung.keycloak-2fa-sms-authenticator.jar` should be created.

## Installing
1. Go to https://github.com/netzbegruenung/keycloak-2fa-sms-authenticator/releases and download
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

## Usage
1. Add a new execution to the 2FA flow of your Browser flow, choose "SMS Authentication (2FA)".
1. Make sure that you name it "sms-2fa". This is currently a hack that will hopefully be fixed. Additional executions with other names can be added. But this first execution will be used for the confirmation SMS when setting up a new phone number.
1. Go into the config of the execution and configure the plugin so that it works with the API of your SMS proivder.

# App Authenticator
Mobile App Authenticator

## API implementation details
The API is based on Keycloaks Action Token Handler to "implement any functionality that initiates or modifies authentication session using action token handler SPI" (Ref. https://www.keycloak.org/docs/latest/server_development/index.html#_action_token_handler_spi)

OpenAPI spec (just for reference, API is managed by keycloak itself): https://github.com/netzbegruenung/keycloak-mfa-plugins/blob/app-authenticator/openapi.yaml

## Setup App Auth Endpoint:

`/realms/realm-id/login-actions/action-token?key=jwt&client_id=account-console&tab_id=someTabId`

### Setup Steps:
1. The URL is transmitted to the device by QR-Code and contains a one-time JWT (in case the device is not authenticated).
2. The mobile device is **supposed to use this URL** to transmit its device data.

### Required additional query parameters:
```
device_id: device ID
device_os: OS
public_key: base64 encoded public key
device_push_id: device push ID (optional)
key_algorithm: public key algorithm e.g. "RSA" (case sensitive)
signature_algorithm: e.g. "SHA512withRSA"
```
Valid Key Algorithms: https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#keyfactory-algorithms

Valid Signature Algorithms: https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#signature-algorithms

### Response
- 201: created app authenticator
- 400: missing query params, invalid/expired JWT

## Authentication Endpoint (basically the same endpoint):

`/realms/realm-id/login-actions/action-token?key=jwt&client_id=account-console&tab_id=someTabId`

### Auth Steps:
1. The URL + JWT is transmitted to the device by firebase. (In the backend both endpoint only differ in the supplied JWT and their token handler. The setup token and auth token both grant access to a single unique server side action)
2. The mobile device is supposed to use this URL to solve the supplied challenge (see below).

### Required additional query parameters:
```
granted: true|false
```

### Signature Header
The proposed Signature header format is based on this RFC draft: https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12

String of comma separated key-values:
```
Signature: keyId:deviceId,created:unixTimestampInMilliseconds,signature:base64encodedSignature
```

Here an example how to create the signature value inside the "Signature" header, which has to be signed:
```
"created:1681897832436,secret:sendByFirebaseOrByChallengeEndPoint,granted:true"
```

### Response
- 204: successfully granted/rejected
- 400: missing or invalid queryParams/signatureHeader, invalid/expired JWT
- 403: signature invalid

The firebase message or the challenge endpoint response contains a secret, which the app is supposed to send its signature back to keycloak for verification.
