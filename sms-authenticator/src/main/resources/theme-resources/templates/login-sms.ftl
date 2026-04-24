<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
	<#if section = "header">
		${msg("smsAuthTitle",realm.displayName)}
	<#elseif section = "form">
		<#if (smsAuthSentToText!)?has_content>
		<div class="${properties.kcFormGroupClass!}" id="kc-sms-sent-hint">
			<p class="pf-v5-c-helper-text" style="word-break: break-all;">${smsAuthSentToText}</p>
		</div>
		</#if>
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
				<div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
					<input name="login" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("doSubmit")}"/>
				</div>
			</div>
		</form>
		<#if smsEnrollmentMode!false>
		<div class="${properties.kcFormGroupClass!}" id="kc-sms-enrollment-actions" style="display:flex; flex-direction:column; gap:0.75rem; width:100%; max-width:100%; margin-top:0.75rem; box-sizing:border-box">
			<form id="kc-sms-enrollment-change" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post" style="width:100%;">
				<input type="hidden" name="sms_enrollment_action" value="change_number" />
				<button type="submit" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}">${msg("smsEnrollmentChangeNumber")}</button>
			</form>
			<form id="kc-sms-enrollment-cancel" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post" style="width:100%;">
				<input type="hidden" name="sms_enrollment_action" value="cancel" />
				<button type="submit" class="${properties.kcButtonClass!} ${properties.kcButtonSecondaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}">${msg("smsEnrollmentCancel")}</button>
			</form>
		</div>
		</#if>
	<#elseif section = "info" >
		${msg("smsAuthInstruction")}
	</#if>
</@layout.registrationLayout>
