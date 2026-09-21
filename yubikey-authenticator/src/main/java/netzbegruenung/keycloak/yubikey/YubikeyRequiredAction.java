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

import jakarta.ws.rs.core.Response;
import netzbegruenung.keycloak.yubikey.credentials.YubikeyCredentialModel;
import org.jboss.logging.Logger;
import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Map;

public class YubikeyRequiredAction implements RequiredActionProvider, CredentialRegistrator {

	public static final String PROVIDER_ID = "yubikey_config";

	private static final Logger logger = Logger.getLogger(YubikeyRequiredAction.class);

	@Override
	public InitiatedActionSupport initiatedActionSupport() {
		return InitiatedActionSupport.SUPPORTED;
	}

	@Override
	public void evaluateTriggers(RequiredActionContext context) {
		// no-op: we do not enforce 2FA enrollment
	}

	/**
	 * Looks up the Yubico admin config by the fixed config alias "yubikey-2fa".
	 * The Required Action runs outside the authenticator execution and has no
	 * direct handle to the authenticator's config, so the admin must name the
	 * execution's config alias exactly "yubikey-2fa".
	 */
	static Map<String, String> yubikeyConfig(RealmModel realm) {
		AuthenticatorConfigModel config = realm.getAuthenticatorConfigByAlias("yubikey-2fa");
		if (config == null) {
			logger.error("Failed to load YubiKey config, no config alias yubikey-2fa found");
			return Map.of();
		}
		return config.getConfig();
	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {
		context.challenge(context.form().createForm("yubikey-enroll.ftl"));
	}

	@Override
	public void processAction(RequiredActionContext context) {
		String otp = context.getHttpRequest().getDecodedFormParameters().getFirst("otp");

		Map<String, String> config = yubikeyConfig(context.getRealm());
		String clientId = config.get("clientId");
		String secretKey = config.get("secretKey");
		String validationUrl = config.getOrDefault("validationUrl", "https://api.yubico.com/wsapi/2.0/verify");

		String publicId = YubicoVerifier.yubikeyPublicId(otp);
		if (otp == null || otp.length() != 44 || publicId == null) {
			handleInvalid(context, "yubikeyEnrollInvalid");
			return;
		}

		if (clientId == null || secretKey == null) {
			logger.error("Cannot verify YubiKey OTP: missing clientId/secretKey in config alias yubikey-2fa");
			handleInvalid(context, "yubikeyEnrollInvalid");
			return;
		}

		YubicoVerifier verifier = new YubicoVerifier(validationUrl, clientId, secretKey);
		YubicoVerifier.Result result = verifier.verify(otp);
		if (result != YubicoVerifier.Result.OK) {
			handleInvalid(context, "yubikeyEnrollInvalid");
			return;
		}

		// guard against duplicate enrollment of the same public id for this user
		boolean alreadyEnrolled = context.getUser().credentialManager()
			.getStoredCredentialsByTypeStream(YubikeyCredentialModel.TYPE)
			.map(m -> YubikeyCredentialModel.createFromModel(m).getYubikeyData().getPublicId())
			.anyMatch(publicId::equals);
		if (alreadyEnrolled) {
			handleInvalid(context, "yubikeyEnrollDuplicate");
			return;
		}

		YubikeyCredentialProvider cp = (YubikeyCredentialProvider)
			context.getSession().getProvider(CredentialProvider.class, YubikeyCredentialProviderFactory.PROVIDER_ID);
		cp.createCredential(context.getRealm(), context.getUser(),
			YubikeyCredentialModel.createYubikey(publicId, "YubiKey " + publicId));

		context.success();
	}

	private void handleInvalid(RequiredActionContext context, String errorMessage) {
		Response challenge = context.form()
			.setError(errorMessage)
			.createForm("yubikey-enroll.ftl");
		context.challenge(challenge);
	}

	@Override
	public void close() {}

	@Override
	public String getCredentialType(KeycloakSession keycloakSession, AuthenticationSessionModel authenticationSessionModel) {
		return YubikeyCredentialModel.TYPE;
	}
}
