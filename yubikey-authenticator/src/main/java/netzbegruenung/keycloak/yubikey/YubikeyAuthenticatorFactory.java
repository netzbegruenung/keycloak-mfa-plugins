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

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class YubikeyAuthenticatorFactory implements AuthenticatorFactory {

	public static final String PROVIDER_ID = "yubikey-authenticator";
	private static final YubikeyAuthenticator SINGLETON = new YubikeyAuthenticator();

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public Authenticator create(KeycloakSession session) {
		return SINGLETON;
	}

	private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
		AuthenticationExecutionModel.Requirement.REQUIRED,
		AuthenticationExecutionModel.Requirement.ALTERNATIVE,
		AuthenticationExecutionModel.Requirement.DISABLED
	};

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return true;
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return List.of(
			new ProviderConfigProperty("validationUrl", "Yubico API URL",
				"Validation server endpoint. Default is Yubico's cloud. Point at a self-hosted YubiKey validation server if desired.",
				ProviderConfigProperty.STRING_TYPE, "https://api.yubico.com/wsapi/2.0/verify"),
			new ProviderConfigProperty("clientId", "Yubico Client ID",
				"The Client ID issued by Yubico (https://upgrade.yubico.com/getapikey/). A small integer.",
				ProviderConfigProperty.STRING_TYPE, ""),
			new ProviderConfigProperty("secretKey", "Yubico Secret Key",
				"The Base64 API secret issued by Yubico alongside the Client ID. Used to sign requests (HMAC-SHA1).",
				ProviderConfigProperty.STRING_TYPE, "")
		);
	}

	@Override
	public String getHelpText() {
		return "Validates a YubiKey OTP against the Yubico validation API.";
	}

	@Override
	public String getDisplayType() {
		return "YubiKey Authentication (2FA)";
	}

	@Override
	public String getReferenceCategory() {
		return "yubikey";
	}

	@Override
	public void init(Config.Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public void close() {
	}

}
