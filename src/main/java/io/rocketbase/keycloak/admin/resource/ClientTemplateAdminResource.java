package io.rocketbase.keycloak.admin.resource;

import org.keycloak.representations.idm.ClientTemplateRepresentation;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import java.util.List;

public class ClientTemplateAdminResource extends BaseAdminResource {

    private static final String URL = "client-templates";
    private static final String URL_WITH_ID = "client-templates/{id}";

    public List<ClientTemplateRepresentation> findAll() {
        ResponseEntity<List<ClientTemplateRepresentation>> response = getRestTemplate().exchange(findBaseUrl(URL),
                HttpMethod.GET,
                null,
                new ParameterizedTypeReference<List<ClientTemplateRepresentation>>() {
                });
        return interpretResponse(response);
    }

    public ClientTemplateRepresentation findById(String id) {
        ResponseEntity<ClientTemplateRepresentation> response = getRestTemplate().exchange(findBaseUrl(URL_WITH_ID),
                HttpMethod.GET,
                null,
                ClientTemplateRepresentation.class,
                id);
        return interpretResponse(response);
    }

    public ClientTemplateRepresentation create(ClientTemplateRepresentation clientTemplate) {
        ResponseEntity<Void> response = getRestTemplate().exchange(findBaseUrl(URL),
                HttpMethod.POST,
                new HttpEntity<>(clientTemplate),
                Void.class);
        return interpretCreatedResponse(response, ClientTemplateRepresentation.class);
    }

    public ClientTemplateRepresentation update(String id, ClientTemplateRepresentation clientTemplate) {
        ResponseEntity<Void> response = getRestTemplate().exchange(findBaseUrl(URL_WITH_ID),
                HttpMethod.PUT,
                new HttpEntity<>(clientTemplate),
                Void.class,
                id);
        interpretUpdatedResponse(response);
        return findById(id);
    }

    public void delete(String id) {
        ResponseEntity<Void> response = getRestTemplate().exchange(findBaseUrl(URL_WITH_ID),
                HttpMethod.DELETE,
                null,
                Void.class,
                id);
        interpretUpdatedResponse(response);
    }

}
