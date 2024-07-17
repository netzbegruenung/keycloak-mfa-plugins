<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
	<#if section = "header">
		${msg("smsPhoneNumberTitle",realm.displayName)}
	<#elseif section = "form">
		<form onsubmit="phonenumber.disabled = true; return true;" id="kc-sms-code-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
			<div class="${properties.kcFormGroupClass!}">
				<div class="${properties.kcLabelWrapperClass!}">
					<label for="code" class="${properties.kcLabelClass!}">${msg("smsPhoneNumberLabel")}</label>
				</div>
				<div class="${properties.kcInputWrapperClass!}">
					<input type="tel" id="code" pattern="[0-9\+\-\.\ ]" name="mobile_number" class="${properties.kcInputClass!}" placeholder="${mobileInputFieldPlaceholder!}" autofocus />
				</div>
			</div>
			<div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
				<div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
					<div class="${properties.kcFormOptionsWrapperClass!}">
						<span><a href="/">${msg("backToApplication")?no_esc}</a></span>
					</div>
				</div>

				<div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
					<input name="phonenumber" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("doSubmitMobile")}" />
				</div>
			</div>
		</form>
	<#elseif section = "info" >
		${msg("smsPhoneNumberInstructions")}
	</#if>
</@layout.registrationLayout>
