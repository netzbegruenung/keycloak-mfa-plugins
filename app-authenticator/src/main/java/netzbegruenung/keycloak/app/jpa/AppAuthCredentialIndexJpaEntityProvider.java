package netzbegruenung.keycloak.app.jpa;

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;

import java.util.Collections;
import java.util.List;

public class AppAuthCredentialIndexJpaEntityProvider implements JpaEntityProvider {
	@Override
	public List<Class<?>> getEntities() {
		return Collections.singletonList(AppAuthCredentialIndex.class);
	}

	@Override
	public String getChangelogLocation() {
		return "META-INF/app-credential-index-changelog.xml";
	}

	@Override
	public String getFactoryId() {
		return AppAuthCredentialIndexJpaEntityProviderFactory.ID;
	}

	@Override
	public void close() {

	}
}
