package netzbegruenung.keycloak.authenticator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.vault.VaultStringSecret;
import org.keycloak.vault.VaultTranscriber;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

public class VaultConfigSecretsTest {

	private static final String API_TOKEN = "apitoken";

	private KeycloakSession session;
	private VaultTranscriber vault;
	private VaultStringSecret secret;

	@BeforeEach
	public void setup() {
		session = mock(KeycloakSession.class);
		vault = mock(VaultTranscriber.class);
		secret = mock(VaultStringSecret.class);
	}

	@Test
	public void resolvesRequestedKeyFromVault() {
		when(session.vault()).thenReturn(vault);
		when(vault.getStringSecret("${vault.sms_api_secret}")).thenReturn(secret);
		when(secret.get()).thenReturn(Optional.of("s3cr3t"));

		Map<String, String> resolved = VaultConfigSecrets.resolve(
			session, Map.of("apiurl", "https://sms.example", API_TOKEN, "${vault.sms_api_secret}"), API_TOKEN);

		assertEquals("s3cr3t", resolved.get(API_TOKEN), "requested key is resolved from the vault");
		assertEquals("https://sms.example", resolved.get("apiurl"), "other config is untouched");
		verify(secret).close();
	}

	@Test
	public void resolvesMultipleRequestedKeys() {
		VaultStringSecret second = mock(VaultStringSecret.class);
		when(session.vault()).thenReturn(vault);
		when(vault.getStringSecret("${vault.token}")).thenReturn(secret);
		when(secret.get()).thenReturn(Optional.of("tok"));
		when(vault.getStringSecret("${vault.pass}")).thenReturn(second);
		when(second.get()).thenReturn(Optional.of("pw"));

		Map<String, String> resolved = VaultConfigSecrets.resolve(
			session, Map.of(API_TOKEN, "${vault.token}", "apipassword", "${vault.pass}"), API_TOKEN, "apipassword");

		assertEquals("tok", resolved.get(API_TOKEN));
		assertEquals("pw", resolved.get("apipassword"));
	}

	@Test
	public void passesThroughNonVaultValue() {
		// A non-vault value resolves to itself in Keycloak's transcriber.
		when(session.vault()).thenReturn(vault);
		when(vault.getStringSecret("plain-token")).thenReturn(secret);
		when(secret.get()).thenReturn(Optional.of("plain-token"));

		Map<String, String> resolved = VaultConfigSecrets.resolve(session, Map.of(API_TOKEN, "plain-token"), API_TOKEN);

		assertEquals("plain-token", resolved.get(API_TOKEN), "plaintext value stays usable");
	}

	@Test
	public void fallsBackToLiteralWhenVaultSecretMissing() {
		// An unresolvable vault expression yields an empty Optional; keep the literal, not null.
		when(session.vault()).thenReturn(vault);
		when(vault.getStringSecret("${vault.missing}")).thenReturn(secret);
		when(secret.get()).thenReturn(Optional.empty());

		Map<String, String> resolved = VaultConfigSecrets.resolve(session, Map.of(API_TOKEN, "${vault.missing}"), API_TOKEN);

		assertEquals("${vault.missing}", resolved.get(API_TOKEN), "unresolved expression falls back to the literal");
	}

	@Test
	public void emptyValueIsNoOp() {
		Map<String, String> config = Map.of("apiurl", "https://sms.example", API_TOKEN, "");

		assertEquals(config, VaultConfigSecrets.resolve(session, config, API_TOKEN));
		verifyNoInteractions(session);
	}

	@Test
	public void missingKeyIsNoOp() {
		Map<String, String> config = Map.of("apiurl", "https://sms.example");

		assertEquals(config, VaultConfigSecrets.resolve(session, config, API_TOKEN));
		verifyNoInteractions(session);
	}

	@Test
	public void noRequestedKeysIsNoOp() {
		Map<String, String> config = Map.of(API_TOKEN, "${vault.sms_api_secret}");

		assertEquals(config, VaultConfigSecrets.resolve(session, config));
		verifyNoInteractions(session);
	}
}
