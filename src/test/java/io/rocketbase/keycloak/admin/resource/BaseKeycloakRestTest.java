package io.rocketbase.keycloak.admin.resource;

import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.assertj.core.util.Lists;
import org.junit.After;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("integrationtest")
public abstract class BaseKeycloakRestTest {

    @Resource
    private TestRestTemplate testRestTemplate;

    @Value("${keycloak.server.baseuri}")
    private String keycloakUri;

    @Resource
    private org.springframework.core.io.Resource keycloakConfig;

    private RestTemplate restTemplate;

    @Before
    public void setup() throws Exception {
        String token = getToken();

        restTemplate = testRestTemplate.getRestTemplate();
        restTemplate.setErrorHandler(new BaseAdminResource.NoopResponseErrorHandler());

        restTemplate.setInterceptors(Lists.newArrayList((request, body, execution) -> {
            request.getHeaders()
                    .set(HttpHeaders.AUTHORIZATION, "Bearer " + token);
            return execution.execute(request, body);
        }));
    }

    @After
    public void tearDown() throws Exception {
        restTemplate.setInterceptors(new ArrayList<>());
        restTemplate.setErrorHandler(new DefaultResponseErrorHandler());
    }


    protected String getToken() throws IOException {
        return getAdminUserToken().getToken();
    }


    protected AccessTokenResponse getDemoUserToken() throws IOException {
        return getToken("demo", "demo");
    }

    protected AccessTokenResponse getAdminUserToken() throws IOException {
        return getToken("admin", "admin");
    }

    protected AccessTokenResponse getSuperAdminUserToken() throws IOException {
        return getToken("superadmin", "superadmin");
    }


    protected HttpHeaders createAuthorizationHeaders(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        return headers;
    }

    protected AccessTokenResponse getToken(String username, String password) throws IOException {
        CloseableHttpClient client = HttpClientBuilder.create()
                .build();
        try {
            HttpPost post = new HttpPost(KeycloakUriBuilder.fromUri(keycloakUri + "/auth")
                    .path(ServiceUrlConstants.TOKEN_PATH)
                    .build("test"));
            List<NameValuePair> formparams = new ArrayList<NameValuePair>();
            formparams.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, "password"));
            formparams.add(new BasicNameValuePair("username", username));
            formparams.add(new BasicNameValuePair("password", password));

            //will obtain a token on behalf of angular-product-app
            formparams.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ID, "rest"));


            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
            post.setEntity(form);
            CloseableHttpResponse response = client.execute(post);
            int status = response.getStatusLine()
                    .getStatusCode();
            org.apache.http.HttpEntity entity = response.getEntity();
            if (status != 200) {
                throw new IOException("Bad status: " + status);
            }
            if (entity == null) {
                throw new IOException("No Entity");
            }
            InputStream is = entity.getContent();
            try {
                AccessTokenResponse tokenResponse = JsonSerialization.readValue(is, AccessTokenResponse.class);
                return tokenResponse;
            } finally {
                try {
                    is.close();
                } catch (IOException ignored) {
                }
            }
        } finally {
            client.close();
        }
    }

    protected KeycloakDeployment getKeycloakDeployment() throws Exception {
        KeycloakDeployment build = KeycloakDeploymentBuilder.build(keycloakConfig.getInputStream());
        return build;
    }


}
