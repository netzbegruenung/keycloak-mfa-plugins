package netzbegruenung.keycloak.app;

import org.keycloak.testframework.ui.page.AbstractLoginPage;
import org.keycloak.testframework.ui.webdriver.ManagedWebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

/**
 * app-auth-setup.ftl - the QR-code / action-token page for the app-register required action.
 * The page's own JS auto-submits {@code kc-app-authentication} once an SSE "ready" event
 * arrives, but SSE is a non-functional stub under the HtmlUnit WebDriver this framework uses
 * by default, so the test submits the form directly instead of waiting on that JS.
 */
public class AppAuthSetupPage extends AbstractLoginPage {

	@FindBy(name = "actiontoken")
	private WebElement actionTokenInput;

	@FindBy(id = "kc-app-authentication")
	private WebElement form;

	public AppAuthSetupPage(ManagedWebDriver driver) {
		super(driver);
	}

	@Override
	public String getExpectedPageId() {
		return "login-app-auth-setup";
	}

	public String getActionTokenUrl() {
		return actionTokenInput.getAttribute("value");
	}

	public void submit() {
		form.submit();
	}
}
