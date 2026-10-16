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
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.authenticator;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Admin REST endpoints mounted at /realms/{realm}/sms-enrollment/..., backed by
 * a bearer access token whose user holds the realm-management "manage-users"
 * client role (the same permission the admin REST API requires for user
 * updates). They run the same auto-enrollment the required action performs at
 * login time, so 2FA is enforced on the user's first login instead of being
 * enrolled only after it.
 */
public class SmsEnrollmentResource {

	private static final Logger logger = Logger.getLogger(SmsEnrollmentResource.class);

	private final KeycloakSession session;

	public SmsEnrollmentResource(KeycloakSession session) {
		this.session = session;
	}

	/**
	 * Enroll a single user: create the mobile-number credential from the
	 * configured user attribute.
	 */
	@POST
	@Path("users/{userId}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response enrollUser(@PathParam("userId") String userId) {
		RealmModel realm = requireCaller();
		UserModel user = session.users().getUserById(realm, userId);
		if (user == null) {
			return Response.status(Response.Status.NOT_FOUND)
				.entity(Map.of("error", "user_not_found", "userId", userId)).build();
		}
		Map<String, Object> result = new HashMap<>();
		result.put("userId", user.getId());
		result.put("username", user.getUsername());
		String mobileNumber = SmsEnrollment.enrollFromAttribute(session, realm, user, getConfig(realm));
		if (mobileNumber == null) {
			result.put("enrolled", false);
		} else {
			result.put("enrolled", true);
			result.put("mobileNumber", mobileNumber);
			logger.infof("Admin-enrolled user %s for SMS 2FA", user.getUsername());
		}
		return Response.ok(result).build();
	}

	/**
	 * Enroll every user that has the configured attribute but no mobile-number
	 * credential yet. Returns the enrolled usernames.
	 */
	@POST
	@Path("enroll-all")
	@Produces(MediaType.APPLICATION_JSON)
	public Response enrollAll() {
		RealmModel realm = requireCaller();
		AuthenticatorConfigModel config = getConfig(realm);
		String mobileNumberAttribute = config == null ? null
			: config.getConfig().getOrDefault("mobileNumberAttribute", "mobile_number");
		if (mobileNumberAttribute == null) {
			return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
				.entity(Map.of("error", "no_config", "detail", "authenticator config alias sms-2fa not found")).build();
		}
		ArrayList<String> enrolled = new ArrayList<>();
		session.users().searchForUserStream(realm, new HashMap<>()).forEach(user -> {
			if (SmsEnrollment.enrollFromAttribute(session, realm, user, config) != null) {
				enrolled.add(user.getUsername());
			}
		});
		Map<String, Object> result = new HashMap<>();
		result.put("attribute", mobileNumberAttribute);
		result.put("enrolled", enrolled);
		result.put("count", enrolled.size());
		return Response.ok(result).build();
	}

	/**
	 * Show the enrollment state of a user (credential present, configured
	 * attribute value).
	 */
	@GET
	@Path("users/{userId}")
	@Produces(MediaType.APPLICATION_JSON)
	public Response getStatus(@PathParam("userId") String userId) {
		RealmModel realm = requireCaller();
		UserModel user = session.users().getUserById(realm, userId);
		if (user == null) {
			return Response.status(Response.Status.NOT_FOUND)
				.entity(Map.of("error", "user_not_found", "userId", userId)).build();
		}
		AuthenticatorConfigModel config = getConfig(realm);
		String mobileNumberAttribute = config == null ? "mobile_number"
			: config.getConfig().getOrDefault("mobileNumberAttribute", "mobile_number");
		Map<String, Object> result = new HashMap<>();
		result.put("userId", user.getId());
		result.put("username", user.getUsername());
		result.put("attribute", mobileNumberAttribute);
		result.put("attributeValue", user.getAttributeStream(mobileNumberAttribute).findFirst().orElse(null));
		result.put("hasCredential", user.credentialManager()
			.getStoredCredentialsByTypeStream(SmsAuthCredentialModel.TYPE)
			.findAny().isPresent());
		return Response.ok(result).build();
	}

	private AuthenticatorConfigModel getConfig(RealmModel realm) {
		return realm.getAuthenticatorConfigByAlias("sms-2fa");
	}

	/**
	 * Authenticate the caller from the Authorization bearer token and require
	 * the realm-management "manage-users" role.
	 */
	private RealmModel requireCaller() {
		HttpHeaders headers = session.getContext().getRequestHeaders();
		String auth = headers == null ? null : headers.getHeaderString(HttpHeaders.AUTHORIZATION);
		if (auth == null || !auth.startsWith("Bearer ")) {
			throw new NotAuthorizedException("Bearer token required");
		}
		RealmModel realm = session.getContext().getRealm();
		AuthenticationManager.AuthResult authResult = AuthenticationManager.verifyIdentityToken(
			session, realm, session.getContext().getUri(), session.getContext().getConnection(),
			true, true, null, false, auth.substring("Bearer ".length()).trim(), headers, verifier -> {});
		if (authResult == null) {
			throw new NotAuthorizedException("Invalid token");
		}
		ClientModel realmManagement = session.clients().getClientByClientId(realm, "realm-management");
		RoleModel manageUsers = realmManagement == null ? null : realmManagement.getRole("manage-users");
		if (manageUsers == null || !authResult.getUser().hasRole(manageUsers)) {
			throw new ForbiddenException("Caller lacks the realm-management manage-users role");
		}
		return realm;
	}
}
