package netzbegruenung.keycloak.dev.config;

import java.io.File;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.platform.PlatformProvider;

public class SimplePlatformProvider implements PlatformProvider {

    private static final org.jboss.logging.Logger logger = Logger.getLogger(SimplePlatformProvider.class);

    Runnable startupHook;
    Runnable shutdownHook;

    @Override
    public String name() {
        return "embedded-platform-provider";
    }

    @Override
    public void onStartup(Runnable startupHook) {
        this.startupHook = startupHook;
        startupHook.run();
    }

    @Override
    public void onShutdown(Runnable shutdownHook) {
        this.shutdownHook = shutdownHook;
    }

    @Override
    public void exit(Throwable cause) {
        logger.fatal("Shutdown Platform", cause);
        exit(1);
    }

    private void exit(int status) {
        new Thread() {
            @Override
            public void run() {
                System.exit(status);
            }
        }.start();
    }
    
    @Override
	public File getTmpDirectory() {
		return new File(System.getProperty("java.io.tmpdir"));
	}

    @Override
    public ClassLoader getScriptEngineClassLoader(Config.Scope scriptProviderConfig) {
        return null;
    }

}