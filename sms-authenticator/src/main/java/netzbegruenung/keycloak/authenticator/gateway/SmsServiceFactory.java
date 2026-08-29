/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.authenticator.gateway;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.vault.VaultStringSecret;
import org.keycloak.vault.VaultTranscriber;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SmsServiceFactory {

	private static final Logger logger = Logger.getLogger(SmsServiceFactory.class);

	/**
	 * Config keys whose values may be Keycloak vault references ({@code ${vault.<key>}})
	 * and therefore must be resolved through the {@link VaultTranscriber} before use.
	 * These are the SMS gateway credentials: the API token and, for HTTP Basic auth, the API user.
	 */
	private static final List<String> SECRET_KEYS = List.of("apitoken", "apiuser");

	/**
	 * Vault-aware variant: resolves any {@code ${vault.<key>}} references in the credential config
	 * (see {@link #SECRET_KEYS}) via the session's {@link VaultTranscriber}, then builds the service.
	 * Plain literal values pass through unchanged, so this is fully backward compatible with configs
	 * that store the token/user inline.
	 */
	public static SmsService get(Map<String, String> config, KeycloakSession session) {
		return get(resolveSecrets(config, session));
	}

	public static SmsService get(Map<String, String> config) {
		if (Boolean.parseBoolean(config.getOrDefault("simulation", "false"))) {
			return (phoneNumber, message) ->
				logger.infof("***** SIMULATION MODE ***** Would send SMS to %s with text: %s", phoneNumber, message);
		} else {
			return new ApiSmsService(config);
		}
	}

	private static Map<String, String> resolveSecrets(Map<String, String> config, KeycloakSession session) {
		if (session == null || config == null) {
			return config;
		}
		Map<String, String> resolved = new HashMap<>(config);
		VaultTranscriber vault = session.vault();
		for (String key : SECRET_KEYS) {
			String value = config.get(key);
			if (value == null || value.isEmpty()) {
				continue;
			}
			// getStringSecret returns the literal value when it is not a ${vault.x} expression, and the
			// resolved secret when it is (an empty Optional only if a referenced vault key is missing).
			try (VaultStringSecret secret = vault.getStringSecret(value)) {
				secret.get().ifPresent(resolvedValue -> resolved.put(key, resolvedValue));
			}
		}
		return resolved;
	}
}
