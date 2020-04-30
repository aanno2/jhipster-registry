package io.github.jhipster.registry.config;

import io.github.jhipster.registry.client.keycloak.*;
import io.github.jhipster.registry.security.AuthoritiesConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.web.client.RestTemplate;

import javax.annotation.PostConstruct;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import static java.util.stream.Collectors.toList;

@Configuration
@Profile(Constants.PROFILE_OAUTH2)
public class OAuth2SecurityBeanConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(OAuth2SecurityBeanConfiguration.class);

    private final Environment environment;
    private Set<String> profiles = new HashSet<>();

    public OAuth2SecurityBeanConfiguration(Environment environment) {
        this.environment = environment;
    }

    @PostConstruct
    void init() {
        profiles.addAll(Arrays.asList(environment.getActiveProfiles()));
    }

    private boolean keycloakInProfile() {
        return profiles.contains("keycloak");
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> oAuth2AccessTokenResponseClient(
        Environment env, TokenSessionStore tokenSessionStore
    ) {
        if (keycloakInProfile()) {
            KeycloakAccessTokenResponseClient result =
                new KeycloakAccessTokenResponseClient(env, tokenSessionStore);
            return result;
        } else {
            DefaultAuthorizationCodeTokenResponseClient result = new DefaultAuthorizationCodeTokenResponseClient();
            return result;
        }
    }

    @Bean
    public HttpSessionOAuth2AuthorizationRequestRepository httpSessionOAuth2AuthorizationRequestRepository() {
        HttpSessionOAuth2AuthorizationRequestRepository result = new HttpSessionOAuth2AuthorizationRequestRepository();
        return result;
    }

    @Bean
    public OidcAuthorizationCodeAuthenticationProvider oidcAuthorizationCodeAuthenticationProvider(
        OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient,
        OAuth2UserService<OidcUserRequest, OidcUser> userService
    ) {
        OidcAuthorizationCodeAuthenticationProvider result = new OidcAuthorizationCodeAuthenticationProvider(
            accessTokenResponseClient, userService);
        return result;
    }

    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oAuth2UserService() {
        if (keycloakInProfile()) {
            KeycloakOidcUserService result = new KeycloakOidcUserService();
            // now automatically set in @PostConstruct
            // result.setJwtDecoder(jwtDecoder);
            // result.setAuthoritiesMapper(authoritiesMapper);
            // result.setKeycloakOidcUserService(keycloakOidcUserService);
            // result.setClaimsToAuthoritiesMapper(new KeycloakClaimsToAuthoritiesMapper());
            return result;
        } else {
            OidcUserService result = new OidcUserService();
            return result;
        }
    }

    @Bean
    public KeycloakLogoutHandler keycloakLogoutHandler(/* RestTemplate restTemplate */) {
        KeycloakLogoutHandler result = new KeycloakLogoutHandler();
        result.setRestTemplate(new RestTemplate());
        return result;
    }

    // stackoverflown: Handle UserRedirectRequiredException
    /*
    @Bean
    public FilterRegistrationBean<OAuth2ClientContextFilter> oauth2FilterRegistration(OAuth2ClientContextFilter filter) {
        FilterRegistrationBean<OAuth2ClientContextFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(filter);
        registrationBean.setOrder(-100);
        return registrationBean;
    }
     */

    @Bean
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        if (keycloakInProfile()) {
            KeycloakAuthoritiesMapper result = new KeycloakAuthoritiesMapper();
            result.setAddPrefixIfNeeded(true);
            result.setConvertGroupsToUppercase(true);
            result.setOnlyAcceptAuthoritiesWithPrefix(false);
            return result;
        } else {
            return (authorities) -> {
                Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

                authorities.forEach(authority -> {
                    OidcUserAuthority oidcUserAuthority = (OidcUserAuthority) authority;
                    OidcUserInfo userInfo = oidcUserAuthority.getUserInfo();
                    if (userInfo == null) {
                        mappedAuthorities.add(new SimpleGrantedAuthority(AuthoritiesConstants.USER));
                    } else {
                        Collection<String> groups = (Collection<String>) userInfo.getClaims().get("groups");
                        if (groups == null) {
                            groups = (Collection<String>) userInfo.getClaims().get("roles");
                        }
                        mappedAuthorities.addAll(groups.stream()
                            .filter(group -> group.startsWith("ROLE_"))
                            .map(SimpleGrantedAuthority::new).collect(toList()));
                    }
                });

                return mappedAuthorities;
            };
        }
    }

    /*
    @Bean
    public OAuth2LoginConfigurer oAuth2LoginConfigurer(
        KeycloakAccessTokenResponseClient accessTokenResponseClient,
        KeycloakOidcUserService keycloakOidcUserService) {
        OAuth2LoginConfigurer result = new OAuth2LoginConfigurer();
        result.tokenEndpoint().accessTokenResponseClient(accessTokenResponseClient);
        result.userInfoEndpoint().userService(keycloakOidcUserService);
        return result;
    }
     */

}
