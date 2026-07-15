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

package netzbegruenung.keycloak.yubikey;

import netzbegruenung.keycloak.yubikey.credentials.YubikeyCredentialModel;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import jakarta.ws.rs.core.Response;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class YubikeyAuthenticator implements Authenticator, CredentialValidator<YubikeyCredentialProvider> {

	private static final Logger logger = Logger.getLogger(YubikeyAuthenticator.class);
	static final String TPL_CODE = "yubikey-login.ftl";

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		context.challenge(context.form().createForm(TPL_CODE));
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		String otp = context.getHttpRequest().getDecodedFormParameters().getFirst("otp");

		Map<String, String> config = getConfig(context);
		String clientId = config.get("clientId");
		String secretKey = config.get("secretKey");
		String validationUrl = config.getOrDefault("validationUrl", "https://api.yubico.com/wsapi/2.0/verify");

		String publicId = YubicoVerifier.yubikeyPublicId(otp);
		if (otp == null || otp.length() != 44 || publicId == null) {
			failInvalid(context);
			return;
		}

		if (clientId == null || secretKey == null) {
			logger.error("Cannot verify YubiKey OTP: missing clientId/secretKey in authenticator config");
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		YubicoVerifier verifier = new YubicoVerifier(validationUrl, clientId, secretKey);
		YubicoVerifier.Result result = verifier.verify(otp);

		if (result == YubicoVerifier.Result.NETWORK_ERROR) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		if (result != YubicoVerifier.Result.OK) {
			failInvalid(context);
			return;
		}

		// ownership check: confirm the public id belongs to a credential enrolled by this user
		boolean enrolled = context.getUser().credentialManager()
			.getStoredCredentialsByTypeStream(YubikeyCredentialModel.TYPE)
			.map(m -> YubikeyCredentialModel.createFromModel(m).getYubikeyData().getPublicId())
			.anyMatch(publicId::equals);

		if (!enrolled) {
			context.getEvent().user(context.getUser()).error("invalid_user_credentials");
			Response challenge = context.form()
				.setError("yubikeyNotEnrolled")
				.createForm(TPL_CODE);
			context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
			return;
		}

		context.success();
	}

	private void failInvalid(AuthenticationFlowContext context) {
		context.getEvent().user(context.getUser()).error("invalid_user_credentials");
		Response challenge = context.form()
			.setError("yubikeyInvalid")
			.createForm(TPL_CODE);
		context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
	}

	/**
	 * Prefer the authenticator's own config; fall back to the fixed "yubikey-2fa"
	 * config alias (used by the Required Action) if none is set on this execution.
	 */
	private Map<String, String> getConfig(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		if (config != null && config.getConfig() != null) {
			return config.getConfig();
		}
		return YubikeyRequiredAction.yubikeyConfig(context.getRealm());
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return getCredentialProvider(session).isConfiguredFor(realm, user, YubikeyCredentialModel.TYPE);
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
		user.addRequiredAction(YubikeyRequiredAction.PROVIDER_ID);
	}

	public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
		return Collections.singletonList((YubikeyRequiredActionFactory) session.getKeycloakSessionFactory()
			.getProviderFactory(RequiredActionProvider.class, YubikeyRequiredAction.PROVIDER_ID));
	}

	@Override
	public void close() {
	}

	@Override
	public YubikeyCredentialProvider getCredentialProvider(KeycloakSession session) {
		return (YubikeyCredentialProvider) session.getProvider(CredentialProvider.class, YubikeyCredentialProviderFactory.PROVIDER_ID);
	}
}
