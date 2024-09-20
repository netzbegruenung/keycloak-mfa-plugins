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
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 */

package netzbegruenung.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Collections;
import java.util.List;

public class SmsAuthenticatorFactory implements AuthenticatorFactory {

	public static final String PROVIDER_ID = "mobile-number-authenticator";
	private static final SmsAuthenticator SINGLETON = new SmsAuthenticator();


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
			new ProviderConfigProperty("length", "Code length", "The number of digits of the generated code.", ProviderConfigProperty.STRING_TYPE, 6),
			new ProviderConfigProperty("ttl", "Time-to-live", "The time to live in seconds for the code to be valid.", ProviderConfigProperty.STRING_TYPE, "300"),
			new ProviderConfigProperty("senderId", "SenderId", "The sender ID is displayed as the message sender on the receiving device.", ProviderConfigProperty.STRING_TYPE, "Keycloak"),
			new ProviderConfigProperty("simulation", "Simulation mode", "In simulation mode, the SMS won't be sent, but printed to the server logs", ProviderConfigProperty.BOOLEAN_TYPE, true),
			new ProviderConfigProperty("countrycode", "Default country prefix", "Default country prefix that is assumed if user does not provide one.", ProviderConfigProperty.STRING_TYPE, "+49"),
			new ProviderConfigProperty("apiurl", "SMS API URL", "The path to the API that receives an HTTP request.", ProviderConfigProperty.STRING_TYPE, "https://example.com/api/sms/send"),
			new ProviderConfigProperty("urlencode", "URL encode data", "By default send a JSON in HTTP POST body. You can URL encode the data instead.", ProviderConfigProperty.BOOLEAN_TYPE, false),
			new ProviderConfigProperty("apitokenattribute", "API Secret Token Attribute (optional)", "Name of attribute that contains your API token/secret. In some APIs the secret is already configured in the path. In this case, this can be left empty.", ProviderConfigProperty.STRING_TYPE, ""),
			new ProviderConfigProperty("apitoken", "API Secret (optional)", "Your API secret. If a Basic Auth user is set, this will be the Basic Auth password.", ProviderConfigProperty.STRING_TYPE, "changeme"),
			new ProviderConfigProperty("apiuser", "Basic Auth Username (optional)", "If set, Basic Auth will be performed. Leave empty if not required.", ProviderConfigProperty.STRING_TYPE, ""),
			new ProviderConfigProperty("messageattribute", "Message Attribute", "The attribute that contains the SMS message text.", ProviderConfigProperty.STRING_TYPE, "text"),
			new ProviderConfigProperty("receiverattribute", "Receiver Phone Number Attribute", "The attribute that contains the receiver phone number.", ProviderConfigProperty.STRING_TYPE, "to"),
			new ProviderConfigProperty("receiverJsonTemplate", "Receiver Phone Number Json value template", "Receiver value structure can be customised to match API requirements.", ProviderConfigProperty.STRING_TYPE, "\"%s\""),
			new ProviderConfigProperty("senderattribute", "Sender Phone Number Attribute", "The attribute that contains the sender phone number. Leave empty if not required.", ProviderConfigProperty.STRING_TYPE, "from"),
			new ProviderConfigProperty("forceSecondFactor", "Force 2FA", "If 2FA authentication is not configured, the user is forced to setup SMS Authentication.", ProviderConfigProperty.BOOLEAN_TYPE, false),
			new ProviderConfigProperty("whitelist", "Excluded from enforced 2FA", "All users with the here selected role are not forced to setup 2FA.", ProviderConfigProperty.ROLE_TYPE, null),
			new ProviderConfigProperty("hideResponsePayload", "Redacted API response log message", "Don't log API response body of SMS send request.", ProviderConfigProperty.BOOLEAN_TYPE, false),
			new ProviderConfigProperty("mobileInputFieldPlaceholder", "Phone number input field placeholder", "The placeholder string user in the phone number input field", ProviderConfigProperty.STRING_TYPE, ""),
			new ProviderConfigProperty("storeInAttribute", "Set phone number as attribute", "Sets the phone number as a user attribute.", ProviderConfigProperty.BOOLEAN_TYPE, false),
			new ProviderConfigProperty("normalizePhoneNumber", "Format phone number", "Normalize the phone number using the E164 standard.", ProviderConfigProperty.BOOLEAN_TYPE, false),
			new ProviderConfigProperty("numberTypeFilters", "Valid number type filters", "A list of valid number types to filter the input phone number by. Possible values are: FIXED_LINE, MOBILE, "
				+ " FIXED_LINE_OR_MOBILE, PAGER, TOLL_FREE, PREMIUM_RATE, SHARED_COST, PERSONAL_NUMBER, VOIP, UAN, VOICEMAIL.", ProviderConfigProperty.MULTIVALUED_STRING_TYPE, Collections.emptyList()),
			new ProviderConfigProperty("forceRetryOnBadFormat", "Ask for new number if checks fail", "Sets an error message and asks the user to re-enter phone number if formatting checks are not successfully passed.", ProviderConfigProperty.BOOLEAN_TYPE, false)
		);
	}

	@Override
	public String getHelpText() {
		return "Validates an OTP sent via SMS to the users mobile phone.";
	}

	@Override
	public String getDisplayType() {
		return "SMS Authentication (2FA)";
	}

	@Override
	public String getReferenceCategory() {
		return "mobile-number";
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
