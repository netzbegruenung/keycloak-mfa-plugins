package netzbegruenung.keycloak.app;

import org.keycloak.testframework.ui.page.AbstractLoginPage;
import org.keycloak.testframework.ui.webdriver.ManagedWebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

/**
 * app-login.ftl - the push-challenge waiting page for the app-authenticator step. Its own JS
 * auto-submits {@code kc-app-authentication} once an SSE "ready" event arrives, but SSE is a
 * non-functional stub under the HtmlUnit WebDriver this framework uses by default, so the test
 * submits the form directly instead of waiting on that JS.
 */
public class AppLoginPage extends AbstractLoginPage {

	@FindBy(id = "kc-app-authentication")
	private WebElement form;

	public AppLoginPage(ManagedWebDriver driver) {
		super(driver);
	}

	@Override
	public String getExpectedPageId() {
		return "login-app-login";
	}

	public void submit() {
		form.submit();
	}
}
