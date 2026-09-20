package netzbegruenung.keycloak.authenticator;

import org.keycloak.testframework.ui.page.AbstractLoginPage;
import org.keycloak.testframework.ui.webdriver.ManagedWebDriver;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

import java.util.Optional;

/**
 * login-sms.ftl (SmsAuthenticator.TPL_CODE). Its code input shares id="code" with
 * mobile_number_form.ftl's phone-number input, disambiguated here since this page's
 * input additionally carries type="number".
 */
public class SmsCodePage extends AbstractLoginPage {

	@FindBy(id = "code")
	private WebElement codeInput;

	@FindBy(css = "#kc-sms-code-login-form input[name='login']")
	private WebElement submitButton;

	@FindBy(css = "#kc-sms-code-login-form input[name='resend']")
	private WebElement resendButton;

	@FindBy(className = "pf-m-success")
	private WebElement successMessage;

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

	public String getResendLabel() {
		return resendButton.getAttribute("value");
	}

	public Optional<String> getSuccessMessage() {
		try {
			return Optional.of(successMessage.getText());
		} catch (NoSuchElementException e) {
			return Optional.empty();
		}
	}
}
