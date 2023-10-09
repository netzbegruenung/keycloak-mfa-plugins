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

OpenAPI spec (just for reference, API is managed by keycloak itself): [openapi.yaml](./openapi.yaml)

## Setup App Auth Endpoint:

`/realms/realm-id/login-actions/action-token?key=jwt&client_id=account-console&tab_id=someTabId`

### Setup Steps:
1. The URL is transmitted to the device by QR-Code and contains a one-time JWT (in case the device is not authenticated).
2. The mobile device is **supposed to use this URL** to transmit its device data.

### Required additional query parameters:
```
device_id: device ID
device_os: OS
public_key: base64 encoded public key (encoded according to the X.509)
device_push_id: device push ID (optional)
key_algorithm: public key algorithm e.g. "RSA" (case sensitive)
signature_algorithm: e.g. "SHA512withRSA"
```
Public Key is assumed to be encoded according to the X.509 standard: https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/spec/X509EncodedKeySpec.html

Valid Key Algorithms: https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#keyfactory-algorithms

Valid Signature Algorithms: https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#signature-algorithms

During signature validation the app authenticator instantiates a KeyFactory object with the provided key_algorithm.
The KeyFactory object will then use the public key specification (public_key) to generate a public key object.
Finally, a signature object is instantiated by signature_algorithm and initialized with the public key object to verify the message signature.

Refs:
- https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyFactory.html#getInstance(java.lang.String)
- https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyFactory.html#generatePublic(java.security.spec.KeySpec)
- https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/Signature.html#getInstance(java.lang.String)

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
Signature: keyId:deviceId,created:unixTimestampInMilliseconds,secret:sendByFirebaseOrByChallengeEndPoint,granted:true,signature:base64encodedSignature
```

To create the signature value inside the "Signature" header, a comma seperated key-value string must be signed and base64 encoded:
```
"keyId:deviceId,created:1681897832436,secret:sendByFirebaseOrByChallengeEndPoint,granted:true"
```

### Response
- 204: successfully granted/rejected
- 400: missing or invalid queryParams/signatureHeader, invalid/expired JWT
- 403: signature invalid

The firebase message or the challenge endpoint response contains a secret, which the app is supposed to send its signature back to keycloak for verification.

## How to test with openssl

1. Generate private key `openssl genpkey -algorithm ed25519 -out private.pem`
2. Generate public key `openssl pkey -in private.pem -pubout -out public.pem`
3. Use this script for signing:
```bash
#!/bin/bash

if [ -z "$1" ]; then
  echo "No message supplied to be signed"
  exit 1
fi

echo -n "$1" > ./.message.bin
openssl pkeyutl -sign -inkey private.pem -out .signature.bin -rawin -in .message.bin
echo ""
echo "${1},signature:$(base64 .signature.bin | tr -d '\n')"
```

The script must be called with a string parameter containing comma seperated key-values
and will return the signature header as described [here](#signature-header)

Example usage:
```wrap
./sign.sh created:1696594860241,\
keyId:device_id,\
secret:LG7mVUUtsPmonuCIDEe59BAAVpU9SQgoBzjtteKs31ltdGdKg2h0ywT8mBorxhYG97afSZugF0654y3kMTTWh2exC5JzekVSbJ32jcoUGveMTUFGtOl1yALxDOM2pvOvgzL0WnKBsiQbQS2u6wzL8ShCO8vbmWVxTjuD9ARaiLyP438vTVhqwmgXjd2l8Ungs78n8El2CFABahfGlKfzbfVOPk5kKgtu8iUDxhhiEawGZCBg1PmlQmaa5Lu7ecn1ZKbr5YXfBZQUcM7aSFjx8TyZeIw5yury3NiTJLl3Tr1wmb9ZwSwtusIeFB5TEx86PCw6CAZZm7wqKawW7E8sEPZUtZJxZ1CkA6M87RkedutylxjAOKvpkHfO9KdizN8OvX2G21nngFwITpnvfh3PMmZRZKvO8TD7Pvt1moXuS975ooLC51uslxvVm64YMLqWspfYTpwqEUZSVekctUWSa0DJC1859H47VKYDPS9JFOeXjd1GPGdWP,\
granted:true

created:1696594860241,\
keyId:device_id,\
secret:LG7mVUUtsPmonuCIDEe59BAAVpU9SQgoBzjtteKs31ltdGdKg2h0ywT8mBorxhYG97afSZugF0654y3kMTTWh2exC5JzekVSbJ32jcoUGveMTUFGtOl1yALxDOM2pvOvgzL0WnKBsiQbQS2u6wzL8ShCO8vbmWVxTjuD9ARaiLyP438vTVhqwmgXjd2l8Ungs78n8El2CFABahfGlKfzbfVOPk5kKgtu8iUDxhhiEawGZCBg1PmlQmaa5Lu7ecn1ZKbr5YXfBZQUcM7aSFjx8TyZeIw5yury3NiTJLl3Tr1wmb9ZwSwtusIeFB5TEx86PCw6CAZZm7wqKawW7E8sEPZUtZJxZ1CkA6M87RkedutylxjAOKvpkHfO9KdizN8OvX2G21nngFwITpnvfh3PMmZRZKvO8TD7Pvt1moXuS975ooLC51uslxvVm64YMLqWspfYTpwqEUZSVekctUWSa0DJC1859H47VKYDPS9JFOeXjd1GPGdWP,\
granted:true,\
signature:hgMHPxnpj9aQCD6p9KjeEr1wzqXR7eFEfRQRa0BrMzD9vFv5/+jFbLsYilQvisOajZORk9ygl32ZmvYfZ8OzBA==
```
