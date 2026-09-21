<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
	<#if section = "header">
		${msg("yubikeyLoginTitle")}
	<#elseif section = "form">
		<form id="kc-yubikey-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
			<div class="${properties.kcFormGroupClass!}">
				<div class="${properties.kcLabelWrapperClass!}">
					<label for="otp" class="${properties.kcLabelClass!}">${msg("yubikeyLoginLabel")}</label>
				</div>
				<div class="${properties.kcInputWrapperClass!}">
					<input type="text" id="otp" name="otp" class="${properties.kcInputClass!}"
						   autocomplete="off" autofocus />
				</div>
			</div>
			<div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
				<input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
					   type="submit" value="${msg("doSubmit")}"/>
			</div>
		</form>
	<#elseif section = "info">
		${msg("yubikeyLoginInstruction")}
	</#if>
</@layout.registrationLayout>
