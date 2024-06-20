<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
    <#if section = "header">
        ${msg("appAuthTitle")}
    <#elseif section = "form">
        <form id="kc-app-authentication" onsubmit="confirm.disabled = true; return true;" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
        </form>
		<#if appAuthStatusUrl??>
			<script type="text/javascript">
				const source = new EventSource("${appAuthStatusUrl?no_esc}");
				source.addEventListener("status", (event) => {
					if (event.data === 'ready') {
						source.close();
						document.getElementById('kc-app-authentication').submit();
					}
				});
			</script>
		</#if>
    <#elseif section = "info" >
        ${msg("appAuthInstructions")}
    </#if>
</@layout.registrationLayout>
