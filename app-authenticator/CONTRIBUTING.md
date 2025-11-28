# Development Notes

-   The API is based on Keycloaks Action Token Handler to "implement any functionality that initiates or modifies authentication session using action token handler SPI" (Ref. <https://www.keycloak.org/docs/latest/server_development/index.html#_action_token_handler_spi>)
-   HTTP respones from action token endpoints cannot be modified. They always return HTML
-   The status code can be modifierd but the response body will be empty

-   Public Key is assumed to be encoded according to the X.509 standard: https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/spec/X509EncodedKeySpec.html

-   Valid Key Algorithms: https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#keyfactory-algorithms

-   Valid Signature Algorithms: https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#signature-algorithms

-   During signature validation the app authenticator instantiates a KeyFactory object with the provided key_algorithm.
    The KeyFactory object will then use the public key specification (public_key) to generate a public key object.
    Finally, a signature object is instantiated by signature_algorithm and initialized with the public key object to verify the message signature.

Refs:

-   https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyFactory.html#getInstance(java.lang.String)
-   https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyFactory.html#generatePublic(java.security.spec.KeySpec)
-   https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/Signature.html#getInstance(java.lang.String)
