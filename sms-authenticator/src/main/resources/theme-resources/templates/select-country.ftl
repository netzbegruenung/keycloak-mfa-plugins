<select id="country-code-select" name="country_code">
    <#list countryList as country>
        <option value="${country.code}">${country.emoji} ${country.name} (${country.code})</option>
    </#list>
</select>