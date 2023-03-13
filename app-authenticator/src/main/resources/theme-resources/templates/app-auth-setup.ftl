<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg("appConfigTitle")}
    <#elseif section = "form">
        <form onsubmit="confirm.disabled = true; return true;" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <ol id="kc-totp-settings">
                <li>
                    <p>${msg("appConfigStep1")}</p>
                </li>
                <li>
                    <p>${msg("appConfigStep2")}</p>
                    <img src="data:image/png;base64, ${appAuthQrCode}" alt="Figure: Barcode" width="512" height="512"><br/>
                </li>
                <li>
                    <p>${msg("appConfigStep3")}</p>
                </li>
                <li>
                    <p>${msg("appConfigStep4")}</p>
                </li>
            </ol>
            <div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input name="confirm" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("appConfigClose")}"/>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>