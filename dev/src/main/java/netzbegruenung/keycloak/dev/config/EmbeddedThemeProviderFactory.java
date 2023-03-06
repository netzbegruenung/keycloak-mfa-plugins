package netzbegruenung.keycloak.dev.config;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Properties;
import org.keycloak.theme.ClasspathThemeResourceProviderFactory;


public class EmbeddedThemeProviderFactory extends ClasspathThemeResourceProviderFactory {
	public static final String ID = "embedded-theme-resources";

	@Override
	public InputStream getResourceAsStream(String path) throws IOException {
		Enumeration<URL> resources = classLoader.getResources(THEME_RESOURCES_RESOURCES);

		while (resources.hasMoreElements()) {
			InputStream is = getResourceAsStream(path, resources.nextElement());

			if (is != null) {
				return is;
			}
		}

		return null;
	}

	@Override
	public Properties getMessages(String baseBundlename, Locale locale) throws IOException {
		Properties messages = new Properties();
		Enumeration<URL> resources = classLoader.getResources(THEME_RESOURCES_MESSAGES + baseBundlename + "_" + locale.toString() + ".properties");

		while (resources.hasMoreElements()) {
			loadMessages(messages, resources.nextElement());
		}

		return messages;
	}

	@Override
	public String getId() {
		return ID;
	}
}
