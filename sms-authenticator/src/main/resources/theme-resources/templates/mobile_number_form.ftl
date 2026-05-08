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
			<div class="pf-v5-c-form__group pf-m-action">
				<div class="pf-v5-c-form__actions">
					<#if isAppInitiatedAction??>
						<input type="submit"
							class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}"
							value="${msg("doSubmitMobile")}"
						/>
						<button type="submit"
							class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!} ${properties.kcButtonLargeClass!}"
							name="cancel-aia" value="true">${msg("doCancel")}
						</button>
					<#else>
						<input type="submit"
							class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
							value="${msg("doSubmitMobile")}"
						/>
					</#if>
				</div>
			</div>
		</form>
	<#elseif section = "info" >
		${msg("smsPhoneNumberInstructions")}
	</#if>
</@layout.registrationLayout>
