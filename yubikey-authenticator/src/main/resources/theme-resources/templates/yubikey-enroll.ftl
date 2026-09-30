<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
	<#if section = "header">
		${msg("yubikeyEnrollTitle")}
	<#elseif section = "form">
		<form id="kc-yubikey-enroll-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
			<div class="${properties.kcFormGroupClass!}">
				<div class="${properties.kcLabelWrapperClass!}">
					<label for="otp" class="${properties.kcLabelClass!}">${msg("yubikeyEnrollLabel")}</label>
				</div>
				<div class="${properties.kcInputWrapperClass!}">
					<input type="text" id="otp" name="otp" class="${properties.kcInputClass!}"
						   autocomplete="off" autofocus />
				</div>
			</div>
			<div class="pf-v5-c-form__group pf-m-action">
				<div class="pf-v5-c-form__actions">
					<#if isAppInitiatedAction??>
						<input type="submit"
							class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}"
							value="${msg("doSubmit")}"
						/>
						<button type="submit"
							class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!} ${properties.kcButtonLargeClass!}"
							name="cancel-aia" value="true">${msg("doCancel")}
						</button>
					<#else>
						<input type="submit"
							class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
							value="${msg("doSubmit")}"
						/>
					</#if>
				</div>
			</div>
		</form>
	<#elseif section = "info">
		${msg("yubikeyEnrollInstruction")}
	</#if>
</@layout.registrationLayout>
