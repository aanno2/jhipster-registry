package io.github.jhipster.registry.config;

import io.github.jhipster.registry.client.keycloak.KeycloakAccessTokenResponseClient;
import io.github.jhipster.registry.client.keycloak.KeycloakAuthoritiesMapper;
import io.github.jhipster.registry.client.keycloak.KeycloakLogoutHandler;
import io.github.jhipster.registry.client.keycloak.KeycloakOidcUserService;
import io.github.jhipster.registry.security.oauth2.AudienceValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;

@Configuration
@Profile(Constants.PROFILE_OAUTH2)
public class OAuth2SecurityBeanConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(OAuth2SecurityBeanConfiguration.class);

    @Value("${kc.base-url}")
    private String kcBaseUrl;

    @Value("${kc.realm}")
    private String realm;

    public OAuth2SecurityBeanConfiguration() {
    }

    @Bean
    public SecurityContextPersistenceFilter securityContextPersistenceFilter() {
        SecurityContextPersistenceFilter result = new SecurityContextPersistenceFilter();
        return result;
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public SessionAuthenticationStrategy sessionAuthenticationStrategy(SessionRegistry sessionRegistry) {
        return new RegisterSessionAuthenticationStrategy(sessionRegistry);
    }

    /*
    @Bean
    public OAuth2AuthorizedClientRepository oAuth2AuthorizedClientService(OAuth2AuthorizedClientService oAuth2AuthorizedClientService) {
        AuthenticatedPrincipalOAuth2AuthorizedClientRepository result = new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(
            oAuth2AuthorizedClientService);
        return result;
    }
     */

    @Bean
    public OAuth2LoginAuthenticationFilter oAuth2LoginAuthenticationFilter(
        ClientRegistrationRepository clientRegistrationRepository, OAuth2AuthorizedClientService authorizedClientService,
        AuthenticationManager authenticationManager, SessionAuthenticationStrategy sessionAuthenticationStrategy) {
        OAuth2LoginAuthenticationFilter result = new OAuth2LoginAuthenticationFilter(
            clientRegistrationRepository, authorizedClientService);
        result.setAuthenticationManager(authenticationManager);
        result.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        return result;
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> oAuth2AccessTokenResponseClient(Environment env) {
        OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> result = new KeycloakAccessTokenResponseClient(env);
        return result;
    }

    @Bean
    public HttpSessionOAuth2AuthorizationRequestRepository httpSessionOAuth2AuthorizationRequestRepository() {
        HttpSessionOAuth2AuthorizationRequestRepository result = new HttpSessionOAuth2AuthorizationRequestRepository();
        return result;
    }

    @Bean
    public OidcAuthorizationCodeAuthenticationProvider oidcAuthorizationCodeAuthenticationProvider(
        OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient,
        KeycloakOidcUserService userService) {
        OidcAuthorizationCodeAuthenticationProvider result = new OidcAuthorizationCodeAuthenticationProvider(
            accessTokenResponseClient, userService);
        return result;
    }

    /*
    @Bean
    public OAuth2LoginAuthenticationProvider oAuth2LoginAuthenticationProvider(
        OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient,
        KeycloakOidcUserService userService)
    {
        OAuth2LoginAuthenticationProvider result = new OAuth2LoginAuthenticationProvider(accessTokenResponseClient,
            userService);
        return result;
    }
     */

    /*
    @Bean
    public OAuth2AuthorizationCodeAuthenticationProvider oAuth2AuthorizationCodeAuthenticationProvider(
        OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> oAuth2AccessTokenResponseClient)
    {
        OAuth2AuthorizationCodeAuthenticationProvider result = new OAuth2AuthorizationCodeAuthenticationProvider(
            oAuth2AccessTokenResponseClient);
        return result;
    }
     */

    @Bean
    public AuthenticationManager authenticationManager(OidcAuthorizationCodeAuthenticationProvider p0) {
        // Potentially there could be more AuthenticationProviders...
        AuthenticationProvider[] array = new AuthenticationProvider[]{p0};
        ProviderManager result = new ProviderManager(Arrays.asList(array));
        return result;
    }

    /*
    @Bean
    public OAuth2AuthorizationCodeGrantFilter oAuth2AuthorizationCodeGrantFilter(
        ClientRegistrationRepository clientRegistrationRepository, OAuth2AuthorizedClientRepository authorizedClientRepository,
        AuthenticationManager authenticationManager)
    {
        OAuth2AuthorizationCodeGrantFilter result = new OAuth2AuthorizationCodeGrantFilter(clientRegistrationRepository,
            authorizedClientRepository, authenticationManager);
        return result;
    }
     */

    @Bean
    public KeycloakOidcUserService keycloakOidcUserService() {

        KeycloakOidcUserService result = new KeycloakOidcUserService();
        // now automatically set in @PostConstruct
        // result.setJwtDecoder(jwtDecoder);
        // result.setAuthoritiesMapper(authoritiesMapper);
        // result.setKeycloakOidcUserService(keycloakOidcUserService);
        // result.setClaimsToAuthoritiesMapper(new KeycloakClaimsToAuthoritiesMapper());
        return result;
    }

    @Bean
    public KeycloakLogoutHandler keycloakLogoutHandler(/* RestTemplate restTemplate */) {
        KeycloakLogoutHandler result = new KeycloakLogoutHandler();
        result.setRestTemplate(new RestTemplate());
        return result;
    }

    /*
    @Bean
    public OAuth2ClientAuthenticationProcessingFilter ssoFilter(
        OAuth2ProtectedResourceDetails details, OAuth2ClientContext oauth2ClientContext,
        ResourceServerTokenServices tokenServices)
    {
        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter(
            "/login/keycloak");
        OAuth2RestTemplate keycloak = new OAuth2RestTemplate(details, oauth2ClientContext);
        filter.setRestTemplate(keycloak);
        filter.setTokenServices(tokenServices);
        return filter;
    }
     */

    /*
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(ClientRegistration clientRegistration) {
        return new InMemoryClientRegistrationRepository(clientRegistration);
    }

    @Bean
    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
        return new HttpSessionOAuth2AuthorizationRequestRepository();
    }
     */

    /*
    @Bean
    @ConfigurationProperties("security.oauth2.client")
    public OAuth2ProtectedResourceDetails oAuth2ProtectedResourceDetails()
    {
        return new AuthorizationCodeResourceDetails();
    }

    @Primary
    @Bean
    @ConfigurationProperties("security.oauth2.resource")
    public OAuth2ResourceServerProperties oAuth2ResourceServerProperties() {
        return new OAuth2ResourceServerProperties();
    }

    @Bean
    public OAuth2RestOperations oAuth2RestOperations(OAuth2ProtectedResourceDetails details, OAuth2ClientContext oauth2ClientContext) {
        return new OAuth2RestTemplate(details, oauth2ClientContext);
    }

    @Bean
    public AccessTokenProvider accessTokenProvider() {
        return new AuthorizationCodeAccessTokenProvider();
    }

    // ??? ClientDetails are not filled-in automatically, i.e. there is something missing...
    @Bean
    public ClientDetails clientDetails() {
        return new BaseClientDetails();
    }
     */

    /*
    @Bean
    public OAuth2AuthenticationManager oAuth2AuthenticationManager(ResourceServerTokenServices tokenServices) {
        OAuth2AuthenticationManager result = new OAuth2AuthenticationManager();
        result.setTokenServices(tokenServices);
        return result;
    }
     */

    /*
    @Bean
    public AuthoritiesExtractor authoritiesExtractor() {
        return new AuthoritiesExtractor() {

            @Override
            public List<GrantedAuthority> extractAuthorities(Map<String, Object> map) {
                Set<GrantedAuthority> result = new HashSet<>();
                extract(result, "roles", map);
                extract(result, "roles2", map);
                extract(result, "groups", map);

                return new ArrayList<>(result);
            }

            private void extract(Set<GrantedAuthority> result, String key, Map<String, Object> map) {
                Object value = map.get(key);
                if (value instanceof Collection) {
                    Collection<String> list = (Collection<String>) value;
                    list.stream()
                        .filter(s -> !StringUtils.isEmpty(s))
                        .map(s -> new SimpleGrantedAuthority(s.trim()))
                        .forEach(result::add);
                } else if (value instanceof String) {
                    result.add(new SimpleGrantedAuthority((String) ((String) value).trim()));
                } else {
                    LOG.warn("Could not map value: " + value);
                }
            }
        };
    }
     */

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
    @SuppressWarnings("unchecked")
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        KeycloakAuthoritiesMapper result = new KeycloakAuthoritiesMapper();
        return result;
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        String issuerUri = kcBaseUrl + "/realms/" + realm;
        NimbusJwtDecoderJwkSupport jwtDecoder = (NimbusJwtDecoderJwkSupport)
            JwtDecoders.fromOidcIssuerLocation(issuerUri);

        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator();
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
        OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer, audienceValidator);

        jwtDecoder.setJwtValidator(withAudience);

        return jwtDecoder;
    }
}
