package netzbegruenung.keycloak.authenticator;

import org.keycloak.testframework.ui.page.AbstractLoginPage;
import org.keycloak.testframework.ui.webdriver.ManagedWebDriver;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

/**
 * login-sms.ftl (SmsAuthenticator.TPL_CODE). Its code input shares id="code" with
 * mobile_number_form.ftl's phone-number input; assertCurrent() tells the pages apart.
 */
public class SmsCodePage extends AbstractLoginPage {

	@FindBy(id = "code")
	private WebElement codeInput;

	@FindBy(css = "#kc-sms-code-login-form input[type='submit']")
	private WebElement submitButton;

	@FindBy(id = "kc-sms-resend")
	private WebElement resendButton;

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

	public void resend() {
		resendButton.click();
	}

	public boolean isResendEnabled() {
		return resendButton.isEnabled();
	}

	/** Submits resend even while the button is disabled, as a client without JS could. */
	public void forceResend() {
		((JavascriptExecutor) driver.driver()).executeScript("arguments[0].disabled = false; arguments[0].click();", resendButton);
	}
}
