<#import "template.ftl" as layout>
<@layout.emailLayout>
${kcSanitize(msg("emailAuthBodyHtml", code, ttl))?no_esc}
</@layout.emailLayout>
