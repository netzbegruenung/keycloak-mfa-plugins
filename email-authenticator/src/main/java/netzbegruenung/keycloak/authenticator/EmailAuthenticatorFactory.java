/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * Copyright 2026 tech@spree GmbH
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
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 * @author tech@spree GmbH
 */

package netzbegruenung.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class EmailAuthenticatorFactory implements AuthenticatorFactory {

	public static final String PROVIDER_ID = "email-otp-authenticator";
	private static final EmailAuthenticator SINGLETON = new EmailAuthenticator();

	private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
		AuthenticationExecutionModel.Requirement.REQUIRED,
		AuthenticationExecutionModel.Requirement.ALTERNATIVE,
		AuthenticationExecutionModel.Requirement.DISABLED
	};

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public Authenticator create(KeycloakSession session) {
		return SINGLETON;
	}

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
	public String getDisplayType() {
		return "Email Authentication (2FA)";
	}

	@Override
	public String getReferenceCategory() {
		return "email-otp";
	}

	@Override
	public String getHelpText() {
		return "Validates an OTP sent via email to the user's verified address.";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return List.of(
			new ProviderConfigProperty("length", "Code length", "The number of digits of the generated code.", ProviderConfigProperty.STRING_TYPE, "6"),
			new ProviderConfigProperty("ttl", "Time-to-live", "The time in seconds the code is valid.", ProviderConfigProperty.STRING_TYPE, "300"),
			new ProviderConfigProperty("forceSecondFactor", "Force 2FA", "If 2FA authentication is not configured, the user is forced to verify their email and use Email OTP.", ProviderConfigProperty.BOOLEAN_TYPE, false)
		);
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
