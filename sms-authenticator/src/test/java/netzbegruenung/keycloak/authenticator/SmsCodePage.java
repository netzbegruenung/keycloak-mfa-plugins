package netzbegruenung.keycloak.authenticator;

import org.keycloak.testframework.ui.page.AbstractLoginPage;
import org.keycloak.testframework.ui.webdriver.ManagedWebDriver;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

/**
 * login-sms.ftl (SmsAuthenticator.TPL_CODE). Its code input shares id="code" with
 * mobile_number_form.ftl's phone-number input, disambiguated here since this page's
 * input additionally carries type="number".
 */
public class SmsCodePage extends AbstractLoginPage {

	@FindBy(id = "code")
	private WebElement codeInput;

	@FindBy(css = "#kc-sms-code-login-form input[type='submit']")
	private WebElement submitButton;

	public SmsCodePage(ManagedWebDriver driver) {
		super(driver);
	}

	@Override
	public String getExpectedPageId() {
		return "login-login-sms";
	}

	public void enterCode(String code) {
		codeInput.clear();
		codeInput.sendKeys(code);
	}

	public void submit() {
		submitButton.click();
	}

	/**
	 * The back link is removed from the markup rather than hidden with CSS, so absence is
	 * checked by counting matches instead of via @FindBy, which would throw.
	 */
	public boolean hasBackToApplicationLink() {
		return !driver.driver().findElements(By.id("backToApplication")).isEmpty();
	}
}
