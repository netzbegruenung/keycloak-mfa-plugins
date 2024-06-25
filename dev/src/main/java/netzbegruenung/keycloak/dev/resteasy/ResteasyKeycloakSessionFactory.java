package netzbegruenung.keycloak.dev.resteasy;

import netzbegruenung.keycloak.dev.config.EmbeddedThemeProviderFactory;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.*;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.services.ServicesLogger;
import org.keycloak.theme.ThemeResourceSpi;

import java.net.URL;
import java.util.*;

public class ResteasyKeycloakSessionFactory extends DefaultKeycloakSessionFactory {

	private static final Logger logger = Logger.getLogger(ResteasyKeycloakSessionFactory.class);

	@Override
	protected Map<Class<? extends Provider>, Map<String, ProviderFactory>> loadFactories(ProviderManager pm) {
		Map<Class<? extends Provider>, Map<String, ProviderFactory>> factoryMap = new HashMap<>();
		Set<Spi> spiList = spis;

		for (Spi spi : spiList) {

			Map<String, ProviderFactory> factories = new HashMap<String, ProviderFactory>();
			factoryMap.put(spi.getProviderClass(), factories);

			String provider = Config.getProvider(spi.getName());
			if (provider != null) {

				ProviderFactory factory = pm.load(spi, provider);
				if (factory == null) {
					continue;
				}

				Config.Scope scope = Config.scope(spi.getName(), provider);
				if (isEnabled(factory, scope)) {
					factory.init(scope);

					if (spi.isInternal() && !isInternal(factory)) {
						ServicesLogger.LOGGER.spiMayChange(factory.getId(), factory.getClass().getName(), spi.getName());
					}

					factories.put(factory.getId(), factory);

					logger.debugv("Loaded SPI {0} (provider = {1})", spi.getName(), provider);
				}

			} else {
				for (ProviderFactory factory : pm.load(spi)) {
					Config.Scope scope = Config.scope(spi.getName(), factory.getId());
					if (isEnabled(factory, scope)) {
						factory.init(scope);

						if (spi.isInternal() && !isInternal(factory)) {
							ServicesLogger.LOGGER.spiMayChange(factory.getId(), factory.getClass().getName(), spi.getName());
						}
						factories.put(factory.getId(), factory);
					} else {
						logger.debugv("SPI {0} provider {1} disabled", spi.getName(), factory.getId());
					}
				}
			}

			if (spi instanceof ThemeResourceSpi) {
				try {
					ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
					Enumeration<URL> resources = classLoader.getResources(EmbeddedThemeProviderFactory.THEME_RESOURCES);

					if (resources.hasMoreElements()) {
						ProviderFactory factory = EmbeddedThemeProviderFactory.class.getDeclaredConstructor().newInstance();
						factories.put(EmbeddedThemeProviderFactory.ID, factory);
					}
				} catch (Exception e) {
					throw new RuntimeException("Failed to install default theme resource provider", e);
				}
			}
		}
		return factoryMap;
	}

	@Override
	public KeycloakSession create() {
		return new ResteasyKeycloakSession(this);
	}
}
