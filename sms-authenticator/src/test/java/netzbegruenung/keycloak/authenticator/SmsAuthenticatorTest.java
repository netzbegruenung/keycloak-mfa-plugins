package netzbegruenung.keycloak.authenticator;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * SmsAuthenticator.addCodeFormAttributes() decides what login-sms.ftl gets to see and is
 * called from four render sites, so it's pinned down here with a recording LoginFormsProvider
 * rather than only through SmsAuthenticatorFlowTest, which needs a running Keycloak.
 */
class SmsAuthenticatorTest {

	private final Map<String, Object> attributes = new HashMap<>();

	/**
	 * LoginFormsProvider is far too wide to implement by hand for one captured call, and the
	 * builder methods have to keep returning the form for the chaining the call sites rely on.
	 */
	private LoginFormsProvider recordingForm() {
		return (LoginFormsProvider) Proxy.newProxyInstance(
			LoginFormsProvider.class.getClassLoader(),
			new Class<?>[]{LoginFormsProvider.class},
			(proxy, method, args) -> {
				if ("setAttribute".equals(method.getName())) {
					attributes.put((String) args[0], args[1]);
					return proxy;
				}
				return null;
			});
	}

	private static AuthenticatorConfigModel configWith(Map<String, String> config) {
		AuthenticatorConfigModel model = new AuthenticatorConfigModel();
		model.setConfig(new HashMap<>(config));
		return model;
	}

	@Test
	@DisplayName("hideBackToApplicationLink=true reaches the template")
	void hidesBackLinkWhenEnabled() {
		SmsAuthenticator.addCodeFormAttributes(recordingForm(), configWith(Map.of("hideBackToApplicationLink", "true")));

		assertEquals(true, attributes.get("hideBackToApplicationLink"));
	}

	@Test
	@DisplayName("hideBackToApplicationLink=false reaches the template")
	void showsBackLinkWhenDisabled() {
		SmsAuthenticator.addCodeFormAttributes(recordingForm(), configWith(Map.of("hideBackToApplicationLink", "false")));

		assertEquals(false, attributes.get("hideBackToApplicationLink"));
	}

	@Test
	@DisplayName("The link stays visible when the option is absent from an existing config")
	void showsBackLinkWhenOptionAbsent() {
		SmsAuthenticator.addCodeFormAttributes(recordingForm(), configWith(Map.of("length", "6")));

		assertEquals(false, attributes.get("hideBackToApplicationLink"));
	}

	@Test
	@DisplayName("A null config does not blow up and leaves the link visible")
	void showsBackLinkWithoutConfig() {
		SmsAuthenticator.addCodeFormAttributes(recordingForm(), null);

		assertEquals(false, attributes.get("hideBackToApplicationLink"));
	}

	@Test
	@DisplayName("A config model without a config map does not blow up either")
	void showsBackLinkWithEmptyConfigModel() {
		SmsAuthenticator.addCodeFormAttributes(recordingForm(), new AuthenticatorConfigModel());

		assertEquals(false, attributes.get("hideBackToApplicationLink"));
	}
}
