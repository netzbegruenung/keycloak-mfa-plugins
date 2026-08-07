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
						this.retryTimeout = null;

						this.connectSSE();
						this.setupLifecycleListeners();
					}

					connectSSE() {
						// If an old connection exists, cleanly close it first
						this.abortConnection();

						console.log('Initiating SSE connection...');
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
						if (this.retryTimeout) clearTimeout(this.retryTimeout);
						this.retryTimeout = setTimeout(() => this.connectSSE(), this.retryInterval);
					}

					// Abort the connection and prevent further retries
					abortConnection() {
						if (this.eventSource) {
							this.eventSource.close();
							this.eventSource = null;
						}
					}

					setupLifecycleListeners() {
                        document.addEventListener('visibilitychange', () => {
                            if (document.visibilityState === 'hidden') {
                                console.log('App moved to background. Tearing down SSE connection...');
                                this.abortConnection();

                                // Clear any pending retry timeouts so it doesn't try to connect while hidden
                                if (this.retryTimeout) clearTimeout(this.retryTimeout);
                            } else if (document.visibilityState === 'visible') {
                                console.log('App returned to foreground. Establishing fresh SSE...');
                                this.connectSSE();
                            }
                        });
                    }
				}

				const sse = new ResilientSSE('${appAuthStatusUrl?no_esc}', 2000);
			</script>
		</#if>
    <#elseif section = "info" >
        ${msg("appAuthInstructions")}
    </#if>
</@layout.registrationLayout>
