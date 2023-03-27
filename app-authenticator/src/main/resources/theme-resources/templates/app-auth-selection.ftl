<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=false; section>
    <#if section = "header" || section = "show-username">
        <script type="text/javascript">
            function fillAndSubmit(authExecId) {
                document.getElementById('app-credential-hidden-input').value = authExecId;
                document.getElementById('kc-select-app-credential').submit();
            }
        </script>
        <#if section = "header">
            ${msg("loginChooseAuthenticator")}
        </#if>
    <#elseif section = "form">

        <form id="kc-select-app-credential" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcSelectAuthListClass!}">
                <#list appCredentials as appCredential>
                    <div class="${properties.kcSelectAuthListItemClass!}" onclick="fillAndSubmit('${appCredential.id}')">

                        <div class="${properties.kcSelectAuthListItemIconClass!}">
                            <i class="fa fa-mobile" style="font-size: 3rem;"></i>
                        </div>
                        <div class="${properties.kcSelectAuthListItemBodyClass!}">
                            <div class="${properties.kcSelectAuthListItemHeadingClass!}">
                                ${msg('${appCredential.credentialData?eval_json.deviceOs}')}
                            </div>
                            <div class="${properties.kcSelectAuthListItemDescriptionClass!}">
                                ${msg('${appCredential.createdDate?number_to_datetime}')}
                            </div>
                        </div>
                        <div class="${properties.kcSelectAuthListItemFillClass!}"></div>
                        <div class="${properties.kcSelectAuthListItemArrowClass!}">
                            <i class="${properties.kcSelectAuthListItemArrowIconClass!}"></i>
                        </div>
                    </div>
                </#list>
                <input type="hidden" id="app-credential-hidden-input" name="app-credential" />
            </div>
        </form>

    </#if>
</@layout.registrationLayout>
