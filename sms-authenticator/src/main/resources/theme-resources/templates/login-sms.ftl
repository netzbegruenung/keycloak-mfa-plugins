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
					<input type="number" min="0" inputmode="numeric" pattern="[0-9]*" id="code" name="code" class="${properties.kcInputClass!}" autocomplete="off" autofocus />
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
			<#-- A real submit named "resend": PhoneValidationRequiredAction.processAction sees the parameter
			     and re-enters the challenge, which re-applies the debounce. Needs no JS, and Keycloak's own
			     post-redirect-get keeps the browser from offering to resubmit the form.
			     Secondary + Default: keycloak.v2 defines only the former, the legacy keycloak theme only the
			     latter, and the undefined one renders empty. Block/Large match the primary button. -->
			<div class="${properties.kcFormGroupClass!}">
				<div id="kc-form-buttons-resend" class="${properties.kcFormButtonsClass!}">
					<input id="kc-sms-resend" name="resend" type="submit" class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" value="${msg("smsAuthResendCode")}"/>
				</div>
			</div>
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
