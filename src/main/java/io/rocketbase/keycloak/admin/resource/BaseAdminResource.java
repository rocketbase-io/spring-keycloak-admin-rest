package io.rocketbase.keycloak.admin.resource;

import io.rocketbase.keycloak.admin.exception.BadRequestException;
import io.rocketbase.keycloak.admin.exception.InternalServerErrorException;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.client.KeycloakRestTemplate;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import java.io.IOException;
import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@SuppressWarnings("WeakerAccess")
public abstract class BaseAdminResource {

    private static final Pattern REALM_URI_PATTERN = Pattern.compile("(https?://.*/auth)/realms/(.*)");

    @Resource
    private KeycloakRestTemplate restTemplate;

    private NoopResponseErrorHandler errorHandler = new NoopResponseErrorHandler();

    protected RestTemplate getRestTemplate() {
        restTemplate.setErrorHandler(errorHandler);
        return restTemplate;
    }


    protected String findBaseUrl(String resource) {
        KeycloakSecurityContext keycloakSecurityContext = getKeycloakSecurityContext();
        String issuer = keycloakSecurityContext.getToken()
                .getIssuer();
        Matcher matcher = REALM_URI_PATTERN.matcher(issuer);
        if (!matcher.matches()) {
            throw new InternalServerErrorException("issuer in token is not keycloak conform: " + issuer);
        }
        return matcher.group(1) + "/admin/realms/" + matcher.group(2) + "/" + resource;
    }

    private KeycloakSecurityContext getKeycloakSecurityContext() {
        Authentication authentication = SecurityContextHolder.getContext()
                .getAuthentication();
        KeycloakAuthenticationToken token;
        KeycloakSecurityContext context;

        if (authentication == null) {
            throw new InternalServerErrorException("Cannot set authorization header because there is no authenticated principal");
        }

        if (!KeycloakAuthenticationToken.class.isAssignableFrom(authentication.getClass())) {
            throw new InternalServerErrorException(
                    String.format(
                            "Cannot set authorization header because Authentication is of type %s but %s is required",
                            authentication.getClass(), KeycloakAuthenticationToken.class)
            );
        }

        token = (KeycloakAuthenticationToken) authentication;
        context = token.getAccount()
                .getKeycloakSecurityContext();

        return context;
    }

    protected <T> T interpretResponse(ResponseEntity<T> entity) {
        HttpStatus statusCode = entity.getStatusCode();
        if (statusCode
                .is2xxSuccessful()) {
            return entity.getBody();
        }
        if (statusCode.equals(HttpStatus.NOT_FOUND)) {
            return null;
        }
        if (statusCode.is4xxClientError()) {
            throw new BadRequestException(entity.toString());
        }
        throw new InternalServerErrorException(entity.toString());
    }

    protected Void interpretErrorResponse(ResponseEntity<Void> entity) {
        HttpStatus statusCode = entity.getStatusCode();
        if (statusCode.equals(HttpStatus.NOT_FOUND)) {
            return null;
        }
        if (statusCode.is4xxClientError()) {
            throw new BadRequestException(entity.getStatusCode()
                    .getReasonPhrase());
        }
        if (statusCode.is5xxServerError()) {
            throw new InternalServerErrorException(entity.getStatusCode()
                    .getReasonPhrase());
        }
        return null;
    }

    protected <T> T interpretCreatedResponse(ResponseEntity<Void> entity, Class<T> clazz) {
        if (entity.getStatusCode()
                .equals(HttpStatus.CREATED)) {
            URI location = entity.getHeaders()
                    .getLocation();
            if (location != null) {
                return interpretResponse(getRestTemplate().getForEntity(location.toString(), clazz));
            }
        }
        throw new InternalServerErrorException("could not interpret status: " + entity.getStatusCode());
    }

    protected void interpretUpdatedResponse(ResponseEntity<Void> entity) {
        if (!entity.getStatusCode()
                .equals(HttpStatus.NO_CONTENT)) {
            throw new InternalServerErrorException("could not interpret status: " + entity.getStatusCode());
        }
    }


    public static final class NoopResponseErrorHandler implements ResponseErrorHandler {

        public boolean hasError(ClientHttpResponse response) throws IOException {
            return !response.getStatusCode()
                    .is2xxSuccessful();
        }

        public void handleError(ClientHttpResponse response) throws IOException {
            if (response.getStatusCode()
                    .equals(HttpStatus.UNAUTHORIZED)) {
                throw new BadCredentialsException(response.getStatusCode()
                        .getReasonPhrase());
            }
            if (response.getStatusCode()
                    .equals(HttpStatus.FORBIDDEN)) {
                throw new AccessDeniedException(response.getStatusCode()
                        .getReasonPhrase());
            }
        }
    }


}
