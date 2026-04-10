package netzbegruenung.keycloak;

import jakarta.ws.rs.core.Response;
import org.jetbrains.annotations.UnknownNullability;
import org.jspecify.annotations.Nullable;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.*;

import java.util.*;
import java.util.function.Consumer;

import static org.junit.Assert.assertEquals;

public interface KeycloakTestUtils {

	Keycloak getKeycloak();

	default RealmResource findRealmByName(String realm) {
		return getKeycloak()
			.realms()
			.realm(realm);
	}

	default RealmRepresentation createRealm(Consumer<RealmRepresentation> realmRepresentationConsumer) {
		RealmRepresentation realmRepresentation = new RealmRepresentation();
		realmRepresentationConsumer.accept(realmRepresentation);
		return createRealm(realmRepresentation);
	}

	default RealmRepresentation createRealm(RealmRepresentation realmRepresentation) {
		getKeycloak().realms().create(realmRepresentation);
		return findRealmByName(realmRepresentation.getRealm()).toRepresentation();
	}

	public static UserRepresentation createUser(
		RealmResource realm,
		Consumer<UserRepresentation> userRepresentationConsumer,
		Consumer<CredentialRepresentation> credentialRepresentationConsumer
	) {
		UserRepresentation userRepresentation = new UserRepresentation();
		userRepresentationConsumer.accept(userRepresentation);

		CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
		credentialRepresentationConsumer.accept(credentialRepresentation);
		userRepresentation.setCredentials(List.of(credentialRepresentation));

		realm.users().create(userRepresentation);

		return userRepresentation;
	}

	public static void createOrUpdateExecutionConfig(
		RealmResource realm,
		AuthenticationExecutionInfoRepresentation authenticationExecutionInfo,
		Consumer<AuthenticatorConfigRepresentation> authenticatorConfigConsumer
	) {
		var refreshedExecutionInfo = refreshAuthenticationExecutionInfo(realm, authenticationExecutionInfo);
		var authenticatorConfigId = refreshedExecutionInfo.getAuthenticationConfig();
		if (authenticatorConfigId == null) {
			authenticatorConfigId = UUID.randomUUID().toString();
			final var authenticatorConfig = new AuthenticatorConfigRepresentation();
			authenticatorConfig.setId(authenticatorConfigId);
			authenticatorConfig.setAlias(UUID.randomUUID().toString());
			final var response = realm.flows().newExecutionConfig(refreshedExecutionInfo.getId(), authenticatorConfig);
			if (response.getStatus() > 299) {
				throw new RuntimeException("Failed to create execution config: " + response.getStatus() + ", " + response.readEntity(String.class));
			}
			assertEquals(201, response.getStatus());
		}
		final var authenticatorConfig = realm.flows().getAuthenticatorConfig(authenticatorConfigId);
		authenticatorConfigConsumer.accept(authenticatorConfig);
		realm.flows().updateAuthenticatorConfig(authenticatorConfigId, authenticatorConfig);
	}

	private static AuthenticationExecutionInfoRepresentation refreshAuthenticationExecutionInfo(RealmResource realm, AuthenticationExecutionInfoRepresentation authenticationExecutionInfo) {
		final var execution = realm.flows().getExecution(authenticationExecutionInfo.getId());
		final var flow = realm.flows().getFlow(execution.getParentFlow());
		final var executions = realm.flows().getExecutions(flow.getAlias());
		final var executionInfo = executions.stream()
			.filter(exec -> authenticationExecutionInfo.getId().equals(exec.getId()))
			.findFirst()
			.orElse(null);
		return executionInfo;
	}

	public static AuthenticationFlowRepresentation copyFlow(RealmResource realm, String originalAlias, Map<String, Object> parameters) {
		Response copiedFlowResponse = realm.flows().copy(originalAlias, parameters);
		final var location = copiedFlowResponse.getHeaders().getFirst("Location").toString();
		final var copiedFlowId = location.substring(location.lastIndexOf("/") + 1);
		final var copiedFlow = realm.flows().getFlow(copiedFlowId);
		return copiedFlow;
	}

	public static void registerUnregisteredRequiredActionById(RealmResource realm, String providerId) {
		final var requiredAction = realm.flows().getUnregisteredRequiredActions().stream().filter(it -> providerId.equals(it.getProviderId())).findFirst().orElseThrow();
		realm.flows().registerRequiredAction(requiredAction);
	}

	static AuthenticationExecutionInfoRepresentation addExecution(
		RealmResource realm,
		AuthenticationExecutionInfoRepresentation parentExecution,
		String providerId,
		Consumer<AuthenticationExecutionInfoRepresentation> executionConsumer
	) {
		if (parentExecution.getFlowId() == null) {
			throw new RuntimeException("Parent execution has no flow id");
		}
		var topLevelFlow = findTopLevelFlowByExecution(realm, parentExecution);
		final var existingExecutionsWithProvider = realm.flows().getExecutions(topLevelFlow.getAlias()).stream().filter(execution -> providerId.equals(execution.getProviderId())).toList();
		final var flow = realm.flows().getFlow(parentExecution.getFlowId());
		realm.flows().addExecution(flow.getAlias(), Map.of("provider", providerId));
		topLevelFlow = findTopLevelFlowByExecution(realm, parentExecution);
		final var newExecutions = realm.flows().getExecutions(topLevelFlow.getAlias());
		final var newExecution = newExecutions
			.stream()
			.filter(execution -> providerId.equals(execution.getProviderId()))
			.filter(execution -> !existingExecutionsWithProvider.contains(execution))
			.findFirst()
			.orElseThrow();
		executionConsumer.accept(newExecution);
		realm.flows().updateExecutions(topLevelFlow.getAlias(), newExecution);
		return newExecution;
	}

	private static AuthenticationFlowRepresentation findTopLevelFlowByExecution(RealmResource realm, AuthenticationExecutionInfoRepresentation execution) {
		final var allTopLevelFlows = realm.flows().getFlows();
		for (var oneTopLevelFlow : allTopLevelFlows) {
			final var allExecutionsForFlow = realm.flows().getExecutions(oneTopLevelFlow.getAlias());
			final var anyMatch = allExecutionsForFlow.stream().filter(it -> Objects.equals(it.getId(), execution.getId())).findAny();
			if (anyMatch.isPresent()) {
				return oneTopLevelFlow;
			}
		}
		throw new RuntimeException("Could not find top level flow for execution " + execution.getId());
	}

}
