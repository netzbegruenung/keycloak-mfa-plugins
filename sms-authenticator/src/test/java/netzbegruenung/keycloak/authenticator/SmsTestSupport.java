package netzbegruenung.keycloak.authenticator;

import jakarta.ws.rs.core.Response;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.testframework.realm.ManagedRealm;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * Wires the mobile-number-authenticator into a copy of the "browser" flow via the admin
 * REST API. Custom required actions aren't auto-registered for a realm either - an admin
 * normally does this once via "Authentication -> Required Actions -> register", so tests
 * need the same one-time registration step.
 *
 * PhoneNumberRequiredAction/PhoneValidationRequiredAction look up their authenticator config
 * by the hardcoded alias "sms-2fa" (see the module README), so the execution's config alias
 * must be exactly that.
 */
final class SmsTestSupport {

	static final String FLOW_ALIAS = "browser-sms";
	static final String CONFIG_ALIAS = "sms-2fa";
	private static final String PROVIDER_ID = "mobile-number-authenticator";

	private SmsTestSupport() {
	}

	static void registerRequiredAction(ManagedRealm realm, String providerId) {
		realm.admin().flows().getUnregisteredRequiredActions().stream()
			.filter(action -> providerId.equals(action.getProviderId()))
			.findFirst()
			.ifPresent(action -> realm.admin().flows().registerRequiredAction(action));
	}

	static void setupSmsBrowserFlow(ManagedRealm managedRealm, Map<String, String> smsExecutionConfig) {
		RealmResource realm = managedRealm.admin();

		AuthenticationFlowRepresentation copiedFlow = copyFlow(realm, "browser", FLOW_ALIAS);
		AuthenticationExecutionInfoRepresentation conditional2fa = realm.flows().getExecutions(copiedFlow.getAlias())
			.stream()
			.filter(e -> e.getDisplayName() != null && e.getDisplayName().contains("Conditional 2FA"))
			.findFirst()
			.orElseThrow(() -> new IllegalStateException("Conditional 2FA subflow not found in copied browser flow"));

		AuthenticationExecutionInfoRepresentation smsExecution = addExecution(realm, conditional2fa, PROVIDER_ID,
			execution -> execution.setRequirement("ALTERNATIVE"));

		createExecutionConfig(realm, smsExecution, config -> {
			config.setAlias(CONFIG_ALIAS);
			config.getConfig().putAll(smsExecutionConfig);
		});

		var realmRepresentation = realm.toRepresentation();
		realmRepresentation.setBrowserFlow(copiedFlow.getAlias());
		realm.update(realmRepresentation);
	}

	static void updateSmsExecutionConfig(ManagedRealm managedRealm, Map<String, String> overrides) {
		RealmResource realm = managedRealm.admin();
		AuthenticationExecutionInfoRepresentation execution = findSmsExecution(realm);
		String configId = execution.getAuthenticationConfig();
		AuthenticatorConfigRepresentation config = realm.flows().getAuthenticatorConfig(configId);
		config.getConfig().putAll(overrides);
		realm.flows().updateAuthenticatorConfig(configId, config);
	}

	private static AuthenticationExecutionInfoRepresentation findSmsExecution(RealmResource realm) {
		return realm.flows().getExecutions(FLOW_ALIAS)
			.stream()
			.filter(e -> PROVIDER_ID.equals(e.getProviderId()))
			.findFirst()
			.orElseThrow(() -> new IllegalStateException("mobile-number-authenticator execution not found in " + FLOW_ALIAS));
	}

	private static AuthenticationFlowRepresentation copyFlow(RealmResource realm, String originalAlias, String newAlias) {
		try (Response response = realm.flows().copy(originalAlias, Map.of("newName", newAlias))) {
			if (response.getStatus() != 201) {
				throw new IllegalStateException("Failed to copy flow " + originalAlias + ": " + response.getStatus());
			}
		}
		return realm.flows().getFlows().stream()
			.filter(flow -> newAlias.equals(flow.getAlias()))
			.findFirst()
			.orElseThrow();
	}

	private static AuthenticationExecutionInfoRepresentation addExecution(
		RealmResource realm,
		AuthenticationExecutionInfoRepresentation parentExecution,
		String providerId,
		Consumer<AuthenticationExecutionInfoRepresentation> executionConsumer
	) {
		AuthenticationFlowRepresentation subFlow = realm.flows().getFlow(parentExecution.getFlowId());
		realm.flows().addExecution(subFlow.getAlias(), Map.of("provider", providerId));

		AuthenticationExecutionInfoRepresentation newExecution = realm.flows().getExecutions(subFlow.getAlias())
			.stream()
			.filter(execution -> providerId.equals(execution.getProviderId()))
			.findFirst()
			.orElseThrow();

		executionConsumer.accept(newExecution);
		realm.flows().updateExecutions(subFlow.getAlias(), newExecution);
		return newExecution;
	}

	private static void createExecutionConfig(
		RealmResource realm,
		AuthenticationExecutionInfoRepresentation execution,
		Consumer<AuthenticatorConfigRepresentation> configConsumer
	) {
		AuthenticatorConfigRepresentation config = new AuthenticatorConfigRepresentation();
		config.setId(UUID.randomUUID().toString());
		config.setConfig(new HashMap<>());
		configConsumer.accept(config);

		try (Response response = realm.flows().newExecutionConfig(execution.getId(), config)) {
			if (response.getStatus() != 201) {
				throw new IllegalStateException("Failed to create execution config: " + response.getStatus());
			}
		}
	}
}
