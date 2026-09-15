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
					<input name="resend" id="kc-sms-resend" class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("smsAuthResend")}" formnovalidate/>
				</div>
			</div>
		</form>
		<#if resendCooldown?? && resendCooldown gt 0>
			<script>
				(function () {
					var button = document.getElementById("kc-sms-resend");
					var label = button.value;
					var left = ${resendCooldown?c};
					var format = function (seconds) {
						if (seconds < 60) {
							return String(seconds);
						}
						var rest = seconds % 60;
						return Math.floor(seconds / 60) + ":" + (rest < 10 ? "0" : "") + rest;
					};
					var tick = function () {
						if (left <= 0) {
							button.disabled = false;
							button.value = label;
							return;
						}
						button.disabled = true;
						button.value = label + " (" + format(left) + ")";
						left--;
						setTimeout(tick, 1000);
					};
					tick();
				})();
			</script>
		</#if>
	<#elseif section = "info" >
		<#if phoneNumber?? && phoneNumber?has_content>
			<#assign maskedPhone = phoneNumber[0..2] + phoneNumber[3..phoneNumber?length-5]?replace(".", "*") + phoneNumber[phoneNumber?length-4..]>
			${msg("smsAuthInstructionWithPhone", maskedPhone)}
		<#else>
			${msg("smsAuthInstruction")}
		</#if>
	</#if>
</@layout.registrationLayout>
