package io.rocketbase.keycloak.admin.resource;

import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import javax.validation.constraints.NotNull;
import java.util.List;

@Component
@Slf4j
public class UserAdminResource extends BaseAdminResource {

    public List<UserRepresentation> findAllContaining(@NotNull String search) {
        ResponseEntity<List<UserRepresentation>> entity = getRestTemplate().exchange(findBaseUrl("users?search={search}"),
                HttpMethod.GET,
                null,
                new ParameterizedTypeReference<List<UserRepresentation>>() {
                }, search);
        return interpretResponse(entity);
    }

    public UserRepresentation find(@NotNull String keycloakUserId) {
        ResponseEntity<UserRepresentation> entity = getRestTemplate().getForEntity(findBaseUrl("users/{id}"),
                UserRepresentation.class,
                keycloakUserId);
        return interpretResponse(entity);
    }

    public UserRepresentation create(@NotNull UserRepresentation userRepresentation) {
        ResponseEntity<Void> entity = getRestTemplate().postForEntity(findBaseUrl("users"), userRepresentation, Void.class);
        interpretErrorResponse(entity);

        return interpretCreatedResponse(entity, UserRepresentation.class);
    }

    public void updateTemporaryPassword(@NotNull String keycloakUserId, @NotNull String newPassword) {
        CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
        credentialRepresentation.setValue(newPassword);
        credentialRepresentation.setType(CredentialRepresentation.PASSWORD);
        credentialRepresentation.setTemporary(true);

        getRestTemplate().put(findBaseUrl("users/{id}/reset-password"), credentialRepresentation, keycloakUserId);
    }

    public void deleteUser(@NotNull String keycloakUserId) {
        getRestTemplate().delete(findBaseUrl("users/{id}"), keycloakUserId);
    }


    public List<GroupRepresentation> findGroups() {
        ResponseEntity<List<GroupRepresentation>> entity = getRestTemplate().exchange(findBaseUrl("groups"),
                HttpMethod.GET,
                null,
                new ParameterizedTypeReference<List<GroupRepresentation>>() {
                });
        return interpretResponse(entity);
    }

    public List<GroupRepresentation> findGroupsOfUser(@NotNull UserRepresentation user) {
        ResponseEntity<List<GroupRepresentation>> entity = getRestTemplate().exchange(findBaseUrl("users/{userid}/groups"),
                HttpMethod.GET,
                null,
                new ParameterizedTypeReference<List<GroupRepresentation>>() {
                },
                user.getId());
        return interpretResponse(entity);
    }

    public void addGroupToUser(@NotNull UserRepresentation user, @NotNull GroupRepresentation group) {
        ResponseEntity<Void> result = getRestTemplate().exchange(findBaseUrl("users/{id}/groups/{groupid}"),
                HttpMethod.PUT,
                null,
                Void.class,
                user.getId(),
                group.getId());
        interpretResponse(result);
    }


}
