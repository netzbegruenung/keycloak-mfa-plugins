package netzbegruenung.keycloak.app.jpa;

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;

import java.util.Collections;
import java.util.List;

public class ChallengeJpaEntityProvider implements JpaEntityProvider {
	@Override
	public List<Class<?>> getEntities() {
		return Collections.singletonList(Challenge.class);
	}

	@Override
	public String getChangelogLocation() {
		return "META-INF/challenge-changelog.xml";
	}

	@Override
	public String getFactoryId() {
		return ChallengeJpaEntityProviderFactory.ID;
	}

	@Override
	public void close() {

	}
}
