package netzbegruenung.keycloak.authenticator.verification;

import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class GenericSmsVerificationProviderFactory implements SmsVerificationProviderFactory {

	public static final String PROVIDER_ID = "generic";
	private static final GenericSmsVerificationProvider SINGLETON = new GenericSmsVerificationProvider();

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public SmsVerificationProvider create(KeycloakSession session) {
		return SINGLETON;
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return List.of(
			new ProviderConfigProperty("senderId", "SenderId", "The sender ID is displayed as the message sender on the receiving device.", ProviderConfigProperty.STRING_TYPE, "Keycloak"),
			new ProviderConfigProperty("simulation", "Simulation mode", "In simulation mode, the SMS won't be sent, but printed to the server logs", ProviderConfigProperty.BOOLEAN_TYPE, true),
			new ProviderConfigProperty("apiurl", "SMS API URL", "The path to the API that receives an HTTP request.", ProviderConfigProperty.STRING_TYPE, "https://example.com/api/sms/send"),
			new ProviderConfigProperty("getUrl", "SMS API GET URL template", "If your SMS API expects a GET request instead of POST, you can set here a URL template with placeholders: {phone}, {message}, {apitoken}, {senderId}. If empty, a POST request will be sent.", ProviderConfigProperty.STRING_TYPE, ""),
			new ProviderConfigProperty("stripPlusPrefix", "Strip + from phone number", "Remove the leading + from phone numbers before sending. Required for APIs expecting E.164 without + prefix (e.g., BudgetSMS).", ProviderConfigProperty.BOOLEAN_TYPE, false),
			new ProviderConfigProperty("urlencode", "URL encode data", "By default send a JSON in HTTP POST body. You can URL encode the data instead.", ProviderConfigProperty.BOOLEAN_TYPE, false),
			new ProviderConfigProperty("apiTokenInHeader", "Put API Secret Token in Authorization Header", "If set, API Secret will be sent as Authorization Header, 'API Secret Token Attribute' and 'Basic Auth Username' will be ignored.", ProviderConfigProperty.BOOLEAN_TYPE, false),
			new ProviderConfigProperty("apitokenattribute", "API Secret Token Attribute (optional)", "Name of attribute that contains your API token/secret. In some APIs the secret is already configured in the path. In this case, this can be left empty.", ProviderConfigProperty.STRING_TYPE, ""),
			new ProviderConfigProperty("apitoken", "API Secret (optional)", "Your API secret. If a Basic Auth user is set, this will be the Basic Auth password.", ProviderConfigProperty.STRING_TYPE, "changeme"),
			new ProviderConfigProperty("apiuser", "Basic Auth Username (optional)", "If set, Basic Auth will be performed. Leave empty if not required.", ProviderConfigProperty.STRING_TYPE, ""),
			new ProviderConfigProperty("messageattribute", "Message Attribute", "The attribute that contains the SMS message text.", ProviderConfigProperty.STRING_TYPE, "text"),
			new ProviderConfigProperty("receiverattribute", "Receiver Phone Number Attribute", "The attribute that contains the receiver phone number.", ProviderConfigProperty.STRING_TYPE, "to"),
			new ProviderConfigProperty("receiverJsonTemplate", "Receiver Phone Number Json value template", "Receiver value structure can be customised to match API requirements.", ProviderConfigProperty.STRING_TYPE, "\"%s\""),
			new ProviderConfigProperty("senderattribute", "Sender Phone Number Attribute", "The attribute that contains the sender phone number. Leave empty if not required.", ProviderConfigProperty.STRING_TYPE, "from"),
			new ProviderConfigProperty("useUuid", "Use message UUID", "If set, data will contain UUID.", ProviderConfigProperty.BOOLEAN_TYPE, false),
			new ProviderConfigProperty("uuidAttribute", "UUID attribute", "The attribute that contains the UUID. Applicable only when 'Use message UUID' is set.", ProviderConfigProperty.STRING_TYPE, ""),
			new ProviderConfigProperty("jsonTemplate", "Request JSON template", "Custom JSON Body template with \"%s\" placeholders for UUID (if 'Use message UUID' is set), phone number and message (in that order). If empty, default template will be used.", ProviderConfigProperty.TEXT_TYPE, ""),
			new ProviderConfigProperty("hideResponsePayload", "Redacted API response log message", "Don't log API response body of SMS send request.", ProviderConfigProperty.BOOLEAN_TYPE, false)
		);
	}
}
