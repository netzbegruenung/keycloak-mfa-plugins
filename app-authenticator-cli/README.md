# App Authenticator CLI

This is a reference implementation for the client-side logic of the App Authenticator.

## Signature Tokens

The API endpoints require an authentication mechanism that leverages client-side generated keypairs. While drafts for HTTP Message Signatures exist, they are no well-established standards.
[draft-ietf-httpbis-message-signatures](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures).

Instead of implementing concepts from this unfinished draft, the API uses client-side generated JSON Web Tokens (JWTs) as a form of request signature. The JWTs are signed using a private key stored on the client and transmitted in the `x-signature` header.

The client should use the authenticator id as the `kid` claim and use an asymmetric signature algorithm. The acceptable algorithms are:

-   `PS512` with an `RSASSA-PSS` asymmetric key
-   `ES512` with an `EC` asymmetric key

The JWT payload should contain:

-   The user id as `sub` claim, which the client can extract from the `sub` claim of the action token issued by Keycloak via the activation token URL.
-   An expiration time of approximately 30 seconds to mitigate replay attacks.
-   A UUID for the JWT in the `jti` claim, which can be used to implement one-time tokens. The token id should be stored on the Keycloak side at least until the token expires.
-   A `typ` claim similar to the Keycloak action tokens, containing a value for the corresponding endpoint or action, e.g., `get-challenges`.
-   Any additional request parameters that need to be signed.

