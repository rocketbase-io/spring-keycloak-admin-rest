package io.rocketbase.keycloak.admin.resource;

import lombok.extern.slf4j.Slf4j;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.AdapterUtils;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.rotation.AdapterRSATokenVerifier;
import org.keycloak.adapters.spi.KeycloakAccount;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.annotation.Resource;
import java.util.List;
import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@Slf4j
public class UserAdminResourceTest extends BaseKeycloakRestTest {

    @Resource
    private UserAdminResource userKeycloakAdminResource;

    private KeycloakPrincipal<? extends KeycloakSecurityContext> principal;

    protected KeycloakPrincipal<? extends KeycloakSecurityContext> loginSuperAdmin() throws Exception {
        return login(getSuperAdminUserToken());
    }

    private KeycloakPrincipal<? extends KeycloakSecurityContext> login(AccessTokenResponse token) throws Exception {
        KeycloakDeployment keycloakDeployment = getKeycloakDeployment();

        AccessToken accessToken = AdapterRSATokenVerifier.verifyToken(token.getToken(), keycloakDeployment);

        RefreshableKeycloakSecurityContext securityContext = new RefreshableKeycloakSecurityContext(keycloakDeployment, null, token.getToken(),
                accessToken, null, null, null);
        final KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal = new KeycloakPrincipal<>(
                AdapterUtils.getPrincipalName(keycloakDeployment, accessToken), securityContext);

        Set<String> roles = AdapterUtils.getRolesFromSecurityContext(securityContext);
        final KeycloakAccount account = new SimpleKeycloakAccount(principal, roles, securityContext);

        SecurityContextHolder.getContext()
                .setAuthentication(new KeycloakAuthenticationToken(account, false));
        return principal;
    }

    @Override
    @Before
    public void setup() throws Exception {
        super.setup();
        principal = loginSuperAdmin();
        tearDown();
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        List<UserRepresentation> testusers = userKeycloakAdminResource.findAllContaining("testuser");
        for (UserRepresentation testuser : testusers) {
            log.debug("deleting testuser: {}", testuser.getUsername());
            userKeycloakAdminResource.deleteUser(testuser.getId());
        }
    }


    @Test
    public void shouldFindSuperAdmin() {
        // given

        // when
        UserRepresentation result = userKeycloakAdminResource.find(principal.getKeycloakSecurityContext()
                .getToken()
                .getSubject());

        // then
        assertThat(result, notNullValue());
        assertThat(result.getUsername(), is("superadmin"));
    }

    @Test
    public void shouldFindAllAdmins() {
        // given

        // when
        List<UserRepresentation> result = userKeycloakAdminResource.findAllContaining("admin");

        // then
        assertThat(result, notNullValue());
        assertThat(result, hasSize(greaterThanOrEqualTo(2)));
    }

    @Test
    public void shouldCreateTestUser() throws Exception {
        // given
        KeycloakPrincipal<? extends KeycloakSecurityContext> principal = loginSuperAdmin();

        UserRepresentation userRepresentation = new UserRepresentation();
        userRepresentation.setUsername("testuser1");
        userRepresentation.setEmail("testuser1@rocketbase.io");
        userRepresentation.setFirstName("test");
        userRepresentation.setLastName("test");
        userRepresentation.setEnabled(true);

        // when
        UserRepresentation result = userKeycloakAdminResource.create(userRepresentation);

        // then
        assertThat(result, notNullValue());
        assertThat(result.getId(), notNullValue());

        assertThat(result.getUsername(), is("testuser1"));
    }

    @Test
    public void shouldDeleteUser() throws Exception {
        // given

        // when
        shouldCreateTestUser();

        List<UserRepresentation> testusers = userKeycloakAdminResource.findAllContaining("testuser1");
        assertThat(testusers, hasSize(1));
        UserRepresentation testuser1 = testusers.get(0);

        userKeycloakAdminResource.deleteUser(testuser1.getId());
        testusers = userKeycloakAdminResource.findAllContaining("testuser1");

        // then
        assertThat(testusers, hasSize(0));
    }

    @Test
    public void shouldSetTemporaryPassword() {
        // given
        UserRepresentation userRepresentation = new UserRepresentation();
        userRepresentation.setUsername("testuser1");
        userRepresentation.setEmail("testuser1@rocketbase.io");
        userRepresentation.setFirstName("test");
        userRepresentation.setLastName("test");
        userRepresentation.setEnabled(true);
        UserRepresentation result = userKeycloakAdminResource.create(userRepresentation);
        assertThat(result.getRequiredActions(), hasSize(0));

        // when
        userKeycloakAdminResource.updateTemporaryPassword(result.getId(), "test123");
        UserRepresentation testuser = userKeycloakAdminResource.find(result.getId());

        // then
        assertThat(testuser, notNullValue());
        assertThat(testuser.getRequiredActions(), notNullValue());
        assertThat(testuser.getRequiredActions(), hasSize(1));
        assertThat(testuser.getRequiredActions(), hasItem("UPDATE_PASSWORD"));
    }

    @Test
    public void shouldFindAllGroups() {
        // given

        // when
        List<GroupRepresentation> result = userKeycloakAdminResource.findGroups();

        // then
        assertThat(result, notNullValue());
        assertThat(result, hasSize(greaterThan(0)));
        GroupRepresentation group = result.get(0);
        assertThat(group, notNullValue());
        assertThat(group.getName(), notNullValue());
        assertThat(group.getId(), notNullValue());
        assertThat(group.getSubGroups(), notNullValue());
    }

    @Test
    public void shouldFindGroupsOfSuperadminUser() {
        // given

        // when
        AccessToken accessToken = principal.getKeycloakSecurityContext()
                .getToken();
        UserRepresentation user = new UserRepresentation();
        user.setId(accessToken
                .getSubject());
        List<GroupRepresentation> result = userKeycloakAdminResource.findGroupsOfUser(user);

        // then
        assertThat(result, hasSize(1));
        GroupRepresentation superadminGroup = result.get(0);
        assertThat(superadminGroup, notNullValue());
        assertThat(superadminGroup.getName(), is("superadmin"));
    }

    @Test
    public void shouldAddGroupToUser() {
        // given
        UserRepresentation userRepresentation = new UserRepresentation();
        userRepresentation.setUsername("testuser1");
        userRepresentation.setEmail("testuser1@rocketbase.io");
        userRepresentation.setFirstName("test");
        userRepresentation.setLastName("test");
        userRepresentation.setEnabled(true);
        UserRepresentation user = userKeycloakAdminResource.create(userRepresentation);
        assertThat(user.getGroups(), nullValue());

        // when
        List<GroupRepresentation> groups = userKeycloakAdminResource.findGroups();
        assertThat(groups, hasSize(greaterThan(0)));
        GroupRepresentation group = groups.get(0);
        userKeycloakAdminResource.addGroupToUser(user, group);

        List<GroupRepresentation> result = userKeycloakAdminResource.findGroupsOfUser(user);

        // then
        assertThat(result, notNullValue());
        assertThat(result, hasSize(1));
        assertThat(result.get(0)
                .getName(), is(group.getName()));
    }

}