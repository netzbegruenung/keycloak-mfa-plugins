<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/intl-tel-input@25.13.1/build/css/intlTelInput.css">
<script src="https://cdn.jsdelivr.net/npm/intl-tel-input@25.13.1/build/js/intlTelInput.min.js"></script>
<script>
  const input = document.querySelector("#code");
  window.intlTelInput(input, {
<#if itelTelInputOptions?has_content>
  <#list itelTelInputOptions?keys as key>
    <#if itelTelInputOptions[key]?is_sequence>
      ${key}: [
        <#list itelTelInputOptions[key] as item>
            "${item?js_string}"<#sep>,</#sep>
        </#list>
      ],
    <#elseif itelTelInputOptions[key]?is_string>
      ${key}: "${itelTelInputOptions[key]}",
    </#if>
  </#list>
</#if>
    geoIpLookup: callback => {
      fetch("https://ipapi.co/json")
        .then(res => res.json())
        .then(data => callback(data.country_code))
        .catch(() => callback("us"));
    },
    hiddenInput: () => ({ phone: "full_phone" }),
    loadUtils: () => import("https://cdn.jsdelivr.net/npm/intl-tel-input@25.13.1/build/js/utils.js"),
  });
</script>