<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
	<#if section = "header">
		${msg("smsAuthTitle",realm.displayName)}
	<#elseif section = "form">
		<form onsubmit="login.disabled = true; return true;" id="kc-sms-code-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
			<div class="${properties.kcFormGroupClass!}">
				<div class="${properties.kcLabelWrapperClass!}">
					<label for="code" class="${properties.kcLabelClass!}">${msg("smsAuthLabel")}</label>
				</div>
				<div class="${properties.kcInputWrapperClass!}">
					<#-- one-time-code lets iOS and Android offer the code from the SMS. -->
					<input type="text" inputmode="numeric" pattern="[0-9]*" id="code" name="code" class="${properties.kcInputClass!}" autocomplete="one-time-code" autofocus />
				</div>
			</div>
			<div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
				<div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
					<div class="${properties.kcFormOptionsWrapperClass!}">
						<span><a href="/realms/${realm.name}/account">${msg("backToApplication")?no_esc}</a></span>
					</div>
				</div>

				<div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
					<input name="login" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("doSubmit")}"/>
				</div>
			</div>
			<#-- Secondary for keycloak.v2, Default for the legacy theme; each theme leaves the other empty. -->
			<div class="${properties.kcFormGroupClass!}">
				<div id="kc-form-buttons-resend" class="${properties.kcFormButtonsClass!}">
					<input id="kc-sms-resend" name="resend" type="submit" formnovalidate class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" value="${msg("smsAuthResendCode")}"/>
				</div>
			</div>
			<#if resendIn?? && resendIn gt 0>
				<#-- Only a hint: the server refuses early resends either way, and without JS the button just stays enabled. -->
				<script>
					(function (button, seconds) {
						var label = button.value;
						button.disabled = true;
						(function tick() {
							if (seconds > 0) {
								button.value = label + " (" + seconds-- + ")";
								setTimeout(tick, 1000);
							} else {
								button.value = label;
								button.disabled = false;
							}
						})();
					})(document.getElementById("kc-sms-resend"), ${resendIn?c});
				</script>
			</#if>
		</form>
	<#elseif section = "info" >
		<#if phoneNumber?? && phoneNumber?has_content>
			<#assign maskedPhone = phoneNumber[0..2] + phoneNumber[3..phoneNumber?length-5]?replace(".", "*") + phoneNumber[phoneNumber?length-4..]>
			${msg("smsAuthInstructionWithPhone", maskedPhone)}
		<#else>
			${msg("smsAuthInstruction")}
		</#if>
	</#if>
</@layout.registrationLayout>
