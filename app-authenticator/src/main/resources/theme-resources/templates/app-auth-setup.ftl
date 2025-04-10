<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg("appConfigTitle")}
    <#elseif section = "form">
        <form id="kc-app-authentication" onsubmit="confirm.disabled = true; return true;" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
					<p>${msg("appConfigDescription")}</p>
					<img src="data:image/png;base64, ${appAuthQrCode}" alt="Figure: Barcode" width="100%">
					<div class="${properties.kcFormGroupClass!}">
							<div class="${properties.kcLabelWrapperClass!}">
									<label for="actiontoken" class="${properties.kcLabelClass!}">${msg("appAuthSetupActionTokenLabel")}</label>
							</div>
							<div class="${properties.kcInputWrapperClass!}" style="display: flex;">
									<input type="text" name="actiontoken" class="${properties.kcInputClass!}" readonly value="${appAuthActionTokenUrl}" />
									<button type="button" onclick="navigator.clipboard.writeText(actiontoken.value);">
											<i class="fa fa-clipboard"></i>
									</button>
							</div>
					</div>
					<#if isAppInitiatedAction??>
							<button type="submit"
									class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
									name="cancel-aia" value="true" />${msg("doCancel")}
							</button>
					</#if>
        </form>
		<script type="text/javascript">
			const source = new EventSource("${appAuthStatusUrl?no_esc}");
			source.onmessage = (event) => {
				if (event.data === 'ready') {
					source.close();
					document.getElementById('kc-app-authentication').submit();
				}
			}
		</script>
    </#if>
</@layout.registrationLayout>
