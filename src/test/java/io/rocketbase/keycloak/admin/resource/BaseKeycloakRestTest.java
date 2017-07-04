package io.rocketbase.keycloak.admin.resource;

import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;

public abstract class BaseKeycloakRestTest extends BaseRestTest {

    protected KeycloakDeployment getKeycloakDeployment() throws Exception {
        return KeycloakDeploymentBuilder.build(getClass().getResourceAsStream("/realms/keycloak.json"));
    }

}
