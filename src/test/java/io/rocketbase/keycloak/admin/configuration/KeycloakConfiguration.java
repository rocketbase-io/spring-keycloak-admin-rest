package io.rocketbase.keycloak.admin.configuration;

import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.springsecurity.AdapterDeploymentContextFactoryBean;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.client.KeycloakClientRequestFactory;
import org.keycloak.adapters.springsecurity.client.KeycloakRestTemplate;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakPreAuthActionsFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Configuration
@EnableWebSecurity
@ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
public class KeycloakConfiguration extends KeycloakWebSecurityConfigurerAdapter {

    @Autowired
    public KeycloakClientRequestFactory keycloakClientRequestFactory;

    @javax.annotation.Resource
    private Environment environment;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/**")
                .fullyAuthenticated();
    }

    @Bean
    @Override
    protected AdapterDeploymentContext adapterDeploymentContext() throws Exception {
        AdapterDeploymentContextFactoryBean factoryBean;
        factoryBean = new AdapterDeploymentContextFactoryBean(keycloakConfig());
        factoryBean.afterPropertiesSet();
        return factoryBean.getObject();
    }

    @Bean
    public Resource keycloakConfig() throws Exception {
        Pattern pattern = Pattern.compile("\\$\\{([^}]*)\\}");

        StringBuffer buffer = new StringBuffer();
        BufferedReader reader = new BufferedReader(new InputStreamReader(getClass().getResourceAsStream("/realms/keycloak.json")));
        String line = reader.readLine();
        while (line != null) {
            Matcher matcher = pattern.matcher(line);
            boolean replacedLine = false;
            while (matcher.find()) {
                replacedLine = true;
                String property = environment.getProperty(matcher.group(1));
                matcher.appendReplacement(buffer, property);
            }
            if (!replacedLine) {
                buffer.append(line);
            } else {
                matcher.appendTail(buffer);
            }
            line = reader.readLine();
        }
        return new ByteArrayResource(buffer.toString()
                .getBytes());
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public KeycloakRestTemplate keycloakRestTemplate() {
        return new KeycloakRestTemplate(keycloakClientRequestFactory);
    }

    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new NullAuthenticatedSessionStrategy();
    }

    @Bean
    public FilterRegistrationBean keycloakAuthenticationProcessingFilterRegistrationBean(
            KeycloakAuthenticationProcessingFilter filter) {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
        registrationBean.setEnabled(false);
        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean keycloakPreAuthActionsFilterRegistrationBean(
            KeycloakPreAuthActionsFilter filter) {
        FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
        registrationBean.setEnabled(false);
        return registrationBean;
    }

}
