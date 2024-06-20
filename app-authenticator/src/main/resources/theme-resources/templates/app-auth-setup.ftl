<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg("appConfigTitle")}
    <#elseif section = "form">
        <form id="kc-app-authentication" onsubmit="confirm.disabled = true; return true;" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <ol id="kc-app-setup">
                <li>
                    <p>${msg("appConfigStep1")}</p>
                    <img src="data:image/png;base64, ${appAuthQrCode}" alt="Figure: Barcode" width="400" height="400"><br/>
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
                </li>
                <li>
                    <p>${msg("appConfigStep2")}</p>
                </li>
                <li>
                    <p>${msg("appConfigStep3")}</p>
                </li>
            </ol>
            <#if isAppInitiatedAction??>
				<button type="submit"
						class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}"
						name="cancel-aia" value="true" />${msg("doCancel")}
				</button>
            </#if>
        </form>
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
</@layout.registrationLayout>
