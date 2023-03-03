package netzbegruenung.keycloak.dev.config;

import java.util.*;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.exportimport.ExportImportManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.services.DefaultKeycloakSessionFactory;
import org.keycloak.services.managers.ApplianceBootstrap;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resources.*;
import org.keycloak.services.util.JsonConfigProviderFactory;
import org.keycloak.util.JsonSerialization;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import netzbegruenung.keycloak.dev.config.KeycloakServerProperties.AdminUser;

public class EmbeddedKeycloakApplication extends KeycloakApplication {

    private static final org.jboss.logging.Logger logger = Logger.getLogger(KeycloakApplication.class);

    static KeycloakServerProperties keycloakServerProperties;

    protected void loadConfig() {
        JsonConfigProviderFactory factory = new RegularJsonConfigProviderFactory();
        Config.init(factory.create()
            .orElseThrow(() -> new NoSuchElementException("No value present")));
    }

    @Override
	protected ExportImportManager bootstrap() {
		final ExportImportManager exportImportManager = super.bootstrap();
		createMasterRealmAdminUser();
		createBaeldungRealm();

		return exportImportManager;
	}

    @Override
    protected KeycloakSessionFactory createSessionFactory() {
        DefaultKeycloakSessionFactory factory = new EmbeddedKeycloakSessionFactory();
        factory.init();
        return factory;
    }

    private void createMasterRealmAdminUser() {

        KeycloakSession session = getSessionFactory().create();

        ApplianceBootstrap applianceBootstrap = new ApplianceBootstrap(session);

        AdminUser admin = keycloakServerProperties.getAdminUser();

        try {
            session.getTransactionManager()
                .begin();
            applianceBootstrap.createMasterRealmUser(admin.getUsername(), admin.getPassword());
            session.getTransactionManager()
                .commit();
        } catch (Exception ex) {
            logger.warnf("Couldn't create keycloak master admin user: {}", ex.getMessage());
            session.getTransactionManager()
                .rollback();
        }

        session.close();
    }

    private void createBaeldungRealm() {
        KeycloakSession session = getSessionFactory().create();

        try {
            session.getTransactionManager()
                .begin();

            RealmManager manager = new RealmManager(session);
            Resource lessonRealmImportFile = new ClassPathResource(keycloakServerProperties.getRealmImportFile());

            manager.importRealm(JsonSerialization.readValue(lessonRealmImportFile.getInputStream(), RealmRepresentation.class));

            session.getTransactionManager()
                .commit();
        } catch (Exception ex) {
            logger.warnf("Failed to import Realm json file: {}", ex.getMessage());
            session.getTransactionManager()
                .rollback();
        }

        session.close();
    }
}
