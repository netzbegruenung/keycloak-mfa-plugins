package netzbegruenung.keycloak.authenticator;

import org.keycloak.models.KeycloakSession;
import org.keycloak.vault.VaultStringSecret;

import java.util.HashMap;
import java.util.Map;

/** Resolves {@code ${vault.<key>}} config references through Keycloak's vault, keeping secrets out of the database. */
final class VaultConfigSecrets {

	private VaultConfigSecrets() {
	}

	/**
	 * Resolves the given {@code secretKeys} through the vault and returns the updated config; keys the
	 * caller doesn't list are left untouched. Non-vault values resolve to themselves and an
	 * unresolvable reference falls back to the literal (Keycloak logs a warning). The input map is
	 * never mutated.
	 */
	static Map<String, String> resolve(KeycloakSession session, Map<String, String> config, String... secretKeys) {
		Map<String, String> resolved = null;
		for (String key : secretKeys) {
			String value = config.get(key);
			if (value == null || value.isEmpty()) {
				continue;
			}
			try (VaultStringSecret secret = session.vault().getStringSecret(value)) {
				if (resolved == null) {
					resolved = new HashMap<>(config);
				}
				resolved.put(key, secret.get().orElse(value));
			}
		}
		return resolved == null ? config : resolved;
	}
}
