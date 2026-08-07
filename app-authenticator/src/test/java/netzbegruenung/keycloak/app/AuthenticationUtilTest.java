package netzbegruenung.keycloak.app;

import netzbegruenung.keycloak.app.credentials.AppCredentialData;
import org.junit.jupiter.api.Test;
import org.keycloak.models.UserModel;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * AuthenticationUtil's parsing/crypto logic has no Keycloak-runtime dependency beyond a
 * UserModel used only for log messages, so it's exercised here directly with real generated
 * key pairs instead of a full Keycloak/browser integration test.
 */
class AuthenticationUtilTest {

	private final UserModel user = mockUser();

	private static UserModel mockUser() {
		UserModel user = mock(UserModel.class);
		when(user.getUsername()).thenReturn("test-user");
		return user;
	}

	// getSignatureMap

	@Test
	void getSignatureMapParsesAWellFormedHeader() {
		Map<String, String> map = AuthenticationUtil.getSignatureMap(
			List.of("signature:c2ln,keyId:device-1,created:" + System.currentTimeMillis())
		);

		assertEquals("c2ln", map.get("signature"));
		assertEquals("device-1", map.get("keyId"));
	}

	@Test
	void getSignatureMapReturnsNullForEmptyHeaderList() {
		assertNull(AuthenticationUtil.getSignatureMap(Collections.emptyList()));
	}

	@Test
	void getSignatureMapReturnsNullWhenSignatureIsMissing() {
		assertNull(AuthenticationUtil.getSignatureMap(
			List.of("keyId:device-1,created:" + System.currentTimeMillis())
		));
	}

	@Test
	void getSignatureMapReturnsNullWhenKeyIdIsMissing() {
		assertNull(AuthenticationUtil.getSignatureMap(
			List.of("signature:c2ln,created:" + System.currentTimeMillis())
		));
	}

	@Test
	void getSignatureMapReturnsNullWhenCreatedIsMissing() {
		assertNull(AuthenticationUtil.getSignatureMap(
			List.of("signature:c2ln,keyId:device-1")
		));
	}

	@Test
	void getSignatureMapReturnsNullForMalformedHeader() {
		assertNull(AuthenticationUtil.getSignatureMap(List.of("not-a-valid-header")));
	}

	@Test
	void getSignatureMapReturnsNullWhenCreatedIsInTheFuture() {
		long farFuture = System.currentTimeMillis() + 60_000;
		assertNull(AuthenticationUtil.getSignatureMap(
			List.of("signature:c2ln,keyId:device-1,created:" + farFuture)
		));
	}

	@Test
	void getSignatureMapReturnsNullWhenCreatedIsNotANumber() {
		assertNull(AuthenticationUtil.getSignatureMap(
			List.of("signature:c2ln,keyId:device-1,created:not-a-number")
		));
	}

	// getSignatureString

	@Test
	void getSignatureStringJoinsMapEntriesWithColonAndComma() {
		Map<String, String> map = new LinkedHashMap<>();
		map.put("created", "123");
		map.put("secret", "abc");
		map.put("granted", "true");

		assertEquals("created:123,secret:abc,granted:true", AuthenticationUtil.getSignatureString(map));
	}

	// verifyChallenge

	@Test
	void verifyChallengeAcceptsAValidRsaSignature() throws Exception {
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		AppCredentialData credentialData = credentialFor(keyPair.getPublic(), "RSA", "SHA256withRSA");

		String signedData = "created:123,secret:abc,granted:true";
		String signature = sign("SHA256withRSA", keyPair, signedData);

		assertTrue(AuthenticationUtil.verifyChallenge(user, credentialData, signedData, signature));
	}

	@Test
	void verifyChallengeAcceptsAValidEcSignature() throws Exception {
		KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
		AppCredentialData credentialData = credentialFor(keyPair.getPublic(), "EC", "SHA256withECDSA");

		String signedData = "created:123,secret:abc,granted:true";
		String signature = sign("SHA256withECDSA", keyPair, signedData);

		assertTrue(AuthenticationUtil.verifyChallenge(user, credentialData, signedData, signature));
	}

	@Test
	void verifyChallengeRejectsATamperedSignedString() throws Exception {
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		AppCredentialData credentialData = credentialFor(keyPair.getPublic(), "RSA", "SHA256withRSA");

		String signature = sign("SHA256withRSA", keyPair, "created:123,secret:abc,granted:true");

		assertFalse(AuthenticationUtil.verifyChallenge(user, credentialData, "created:123,secret:abc,granted:false", signature));
	}

	@Test
	void verifyChallengeRejectsGarbageSignatureBytes() throws Exception {
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		AppCredentialData credentialData = credentialFor(keyPair.getPublic(), "RSA", "SHA256withRSA");

		String garbageSignature = Base64.getEncoder().encodeToString("not-a-real-signature".getBytes());

		assertFalse(AuthenticationUtil.verifyChallenge(user, credentialData, "created:123,secret:abc,granted:true", garbageSignature));
	}

	@Test
	void verifyChallengeRejectsAnUnsupportedAlgorithmWithoutThrowing() throws Exception {
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		AppCredentialData credentialData = credentialFor(keyPair.getPublic(), "NOT-AN-ALGORITHM", "SHA256withRSA");

		String signature = sign("SHA256withRSA", keyPair, "created:123,secret:abc,granted:true");

		assertFalse(AuthenticationUtil.verifyChallenge(user, credentialData, "created:123,secret:abc,granted:true", signature));
	}

	private static AppCredentialData credentialFor(PublicKey publicKey, String keyAlgorithm, String signatureAlgorithm) {
		String encodedPublicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		return new AppCredentialData(encodedPublicKey, "device-1", "test-os", keyAlgorithm, signatureAlgorithm, "push-1");
	}

	private static String sign(String signatureAlgorithm, KeyPair keyPair, String data) throws Exception {
		Signature signer = Signature.getInstance(signatureAlgorithm);
		signer.initSign(keyPair.getPrivate());
		signer.update(data.getBytes());
		return Base64.getEncoder().encodeToString(signer.sign());
	}
}
