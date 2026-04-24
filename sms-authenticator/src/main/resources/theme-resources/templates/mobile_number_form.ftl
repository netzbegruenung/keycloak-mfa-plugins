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
			<#if countryList?has_content>
				<div class="${properties.kcInputWrapperClass!}" style="display:flex">
					<#include "select-country.ftl">
			<#else>
				<div class="${properties.kcInputWrapperClass!}">
			</#if>
					<input type="tel" id="code" pattern="[0-9\+\-\.\ ]" name="mobile_number" class="${properties.kcInputClass!}" placeholder="${mobileInputFieldPlaceholder!}" autofocus />
				</div>
			</div>
			<div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
				<div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
					<input name="phonenumber" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("doSubmitMobile")}" />
				</div>
			</div>
		</form>
		<div class="${properties.kcFormGroupClass!}" id="kc-sms-enrollment-actions" style="display:flex; flex-direction:column; gap:0.75rem; width:100%; max-width:100%; margin-top:0.75rem; box-sizing:border-box">
			<form id="kc-sms-enrollment-cancel" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post" style="width:100%;">
				<input type="hidden" name="sms_enrollment_action" value="cancel" />
				<button type="submit" class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}">${msg("smsEnrollmentCancel")}</button>
			</form>
		</div>
	<#elseif section = "info" >
		${msg("smsPhoneNumberInstructions")}
	</#if>
</@layout.registrationLayout>
