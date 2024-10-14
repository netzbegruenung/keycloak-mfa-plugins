<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
    <#if section = "header" || section = "show-username">
		<script type="text/javascript">
			function fillAndSubmit(authExecId) {
				document.getElementById('mfa-method-hidden-input').value = authExecId;
				document.getElementById('kc-select-mfa-form').submit();
			}
		</script>
        <#if section = "header">
            ${msg("loginChooseMfa")}
        </#if>
    <#elseif section = "form">

		<form id="kc-select-mfa-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
			<div class="${properties.kcSelectAuthListClass!}">
                <#list mfa! as requiredAction>
					<div class="${properties.kcSelectAuthListItemClass!}" onclick="fillAndSubmit('${requiredAction.providerId}')" id="mfa-${requiredAction.providerId}" style="cursor: pointer;">

						<div class="${properties.kcSelectAuthListItemIconClass!}">
							<i class="${properties.kcSelectAuthListItemIconPropertyClass!} ${properties.kcAuthenticatorDefaultClass!}"></i>
						</div>
						<div class="${properties.kcSelectAuthListItemBodyClass!}">
							<div class="${properties.kcSelectAuthListItemHeadingClass!}">
                                ${msg('${localizationPrefix}.${requiredAction.providerId}')}
							</div>
							<div class="${properties.kcSelectAuthListItemDescriptionClass!}">
                                ${msg('${localizationPrefix}.${requiredAction.providerId}-help-text')}
							</div>
						</div>
					</div>
                </#list>
				<input type="hidden" id="mfa-method-hidden-input" name="mfaMethod" />
			</div>
		</form>
	<#elseif section = "info">
		${msg("loginChooseMfa")}

		<#if isSetupOptional = true>
			<br/>
			<a href="#" onclick="event.preventDefault(); fillAndSubmit('')">${msg("${localizationPrefix}.skipSetup")}</a>
		</#if>
    </#if>
</@layout.registrationLayout>
