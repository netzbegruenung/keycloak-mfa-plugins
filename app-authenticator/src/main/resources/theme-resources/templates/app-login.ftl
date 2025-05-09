<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
    <#if section = "header">
        ${msg("appAuthTitle")}
    <#elseif section = "form">
        <form id="kc-app-authentication" onsubmit="confirm.disabled = true; return true;" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
        </form>
		<#if appAuthStatusUrl??>
			<script type="text/javascript">
				class ResilientSSE {
					constructor(url, retryInterval = 3000) {
						this.url = url;
						this.retryInterval = retryInterval;
						this.eventSource = null;
						this.connectSSE();
					}

					connectSSE() {
						this.eventSource = new EventSource(this.url);

						this.eventSource.onopen = () => {
							console.log('Connected to SSE');
						};

						this.eventSource.onmessage = (event) => {
							if (event.data === 'ready') {
								this.eventSource.close();
								document.getElementById('kc-app-authentication').submit();
							}
						};

						this.eventSource.onerror = () => {
							console.warn('SSE connection lost. Retrying after delay...');
							this.eventSource.close();
							this.scheduleRetry();
						};
					}

					scheduleRetry() {
						setTimeout(() => this.connectSSE(), this.retryInterval);
					}

					// Abort the connection and prevent further retries
					abortConnection() {
						if (this.eventSource) {
							this.eventSource.close(); // Close the SSE connection if open
						}
					}
				}

				const sse = new ResilientSSE('${appAuthStatusUrl?no_esc}', 2000);
			</script>
		</#if>
    <#elseif section = "info" >
        ${msg("appAuthInstructions")}
    </#if>
</@layout.registrationLayout>
