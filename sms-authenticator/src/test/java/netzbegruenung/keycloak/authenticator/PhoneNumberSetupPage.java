package netzbegruenung.keycloak.authenticator;

import org.keycloak.testframework.ui.page.AbstractLoginPage;
import org.keycloak.testframework.ui.webdriver.ManagedWebDriver;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.FindBy;

/** mobile_number_form.ftl - the phone-number entry form for the mobile_number_config required action. */
public class PhoneNumberSetupPage extends AbstractLoginPage {

	@FindBy(name = "mobile_number")
	private WebElement phoneNumberInput;

	public PhoneNumberSetupPage(ManagedWebDriver driver) {
		super(driver);
	}

	@Override
	public String getExpectedPageId() {
		return "login-mobile_number_form";
	}

	public void enterPhoneNumber(String phoneNumber) {
		phoneNumberInput.clear();
		phoneNumberInput.sendKeys(phoneNumber);
	}

	/**
	 * The phone number input's pattern="[0-9\+\-\.\ ]" contains a backslash-escaped space,
	 * which is invalid ECMAScript syntax under the Unicode-aware regex flags ('u'/'v') the
	 * HTML spec requires for compiling the pattern attribute - real browsers fail to compile
	 * it and, per spec, treat the input as if pattern weren't set at all, so this doesn't
	 * affect real users. HtmlUnit (this framework's WebDriver) compiles the same string in a
	 * more lenient mode that tolerates the escape, producing a regex that - lacking a
	 * quantifier - only matches a single character, so a plain click here gets rejected by
	 * HtmlUnit's own constraint validation. Submitting via the DOM API instead of clicking
	 * skips that HtmlUnit-specific validation step.
	 */
	public void submit() {
		((JavascriptExecutor) driver.driver()).executeScript("arguments[0].form.submit();", phoneNumberInput);
	}
}
