package io.github.jhipster.registry.config;

import io.github.jhipster.config.JHipsterProperties;
import io.github.jhipster.registry.security.AuthoritiesConstants;
import io.github.jhipster.registry.security.oauth2.AudienceValidator;
import io.github.jhipster.registry.security.oauth2.AuthorizationHeaderFilter;
import io.github.jhipster.registry.security.oauth2.AuthorizationHeaderUtil;
import io.github.jhipster.registry.security.oauth2.MultiRealmOAuth2ResourceServerConfigurer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.util.StringUtils;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static java.util.stream.Collectors.toList;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Profile(Constants.PROFILE_OAUTH2)
public class OAuth2SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private static final Logger LOG = LoggerFactory.getLogger(OAuth2SecurityConfiguration.class);

    /*
    @Value("${spring.security.oauth2.client.provider.oidc.issuer-uri}")
    private String issuerUri;
    */

    private final JHipsterProperties jHipsterProperties;
    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> oAuth2AccessTokenResponseClient;
    private final OAuth2UserService<OidcUserRequest, OidcUser> userService;
    private final JwtAuthenticationConverter jwtAuthenticationConverter;
    private final JwtDecoder jwtDecoder;

    public OAuth2SecurityConfiguration(JHipsterProperties jHipsterProperties,
        OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient,
        OAuth2UserService<OidcUserRequest, OidcUser> oAuth2UserService,
        JwtAuthenticationConverter jwtAuthenticationConverter,
        JwtDecoder jwtDecoder
        ) {
        this.jHipsterProperties = jHipsterProperties;
        this.oAuth2AccessTokenResponseClient = accessTokenResponseClient;
        this.userService = oAuth2UserService;
        this.jwtAuthenticationConverter = jwtAuthenticationConverter;
        this.jwtDecoder = jwtDecoder;
    }

    /**
     * Needed to get admin/admin account (tp)
     */
    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager(
        SecurityProperties properties,
        ObjectProvider<PasswordEncoder> passwordEncoder) {
        SecurityProperties.User user = properties.getUser();
        List<String> roles = user.getRoles();
        LOG.warn("Adding user " + user.getName() + " with roles " + roles + " from configuration");
        return new InMemoryUserDetailsManager(User.withUsername(user.getName())
            .password(getOrDeducePassword(user, passwordEncoder.getIfAvailable()))
            .roles(StringUtils.toStringArray(roles)).build());
    }

    private String getOrDeducePassword(SecurityProperties.User user,
                                       PasswordEncoder encoder) {
        if (encoder != null) {
            return user.getPassword();
        }
        return "{noop}" + user.getPassword();
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
            .antMatchers("/app/**/*.{js,html}")
            .antMatchers("/swagger-ui/**")
            .antMatchers("/content/**");
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .cors()
        .and()
            .csrf()
            .disable()
            .headers()
            .frameOptions()
            .disable()
// disable basic auth (tp)
//        .and()
//            .httpBasic()
//            .realmName("JHipster Registry")
        .and()
            .httpBasic()
            .disable()
            // without session spring-boot-admin does not work currently (tp)
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
        .and()
            .authorizeRequests()
            .antMatchers("/services/**").authenticated()
            // seems to be needed for (config server) discovery (tp)
            .antMatchers("/api/eureka/**").permitAll()
            .antMatchers("/eureka/**").hasAuthority(AuthoritiesConstants.ADMIN)
            .antMatchers("/config/**").hasAuthority(AuthoritiesConstants.ADMIN)
            .antMatchers("/api/**").authenticated()
            .antMatchers("/management/info").permitAll()
            .antMatchers("/management/health").permitAll()
            // TODO: Allow only spring-boot-admin to access (tp)
            // (but that has proved to be difficult...)
            // .antMatchers("/management/**").hasAuthority(AuthoritiesConstants.ADMIN)
            // ATTENTION tp: At present it is VITAL that nobody from outside the cloud could access this...
            .antMatchers("/management/**").permitAll()
            // Allow spring-boot-admin only for admins
            .antMatchers("/sbadmin/**").hasAuthority(AuthoritiesConstants.ADMIN)
            // Allow registering on eureka
            .antMatchers("/eureka/**").permitAll()
            // Allow using config server
            .antMatchers("/config/**").permitAll()
            // Allow eureka-consul-adapter
            // Endpoints are:
            // datacenter: http://localhost:8761/v1/agent/self
            // Service list: http://localhost:8761/v1/catalog/services
            // Service details: http://localhost:8761/v1/catalog/service/JHIPSTER-REGISTRY
            .antMatchers("/v1/**").permitAll()
// disable oauth2 client stuff  ??? (tp)
        .and()
            .oauth2Client()
            .authorizationCodeGrant()
            .accessTokenResponseClient(oAuth2AccessTokenResponseClient)
            .and()
// there is no login without an oauth2 client (tp)
        .and()
            .oauth2Login()
            .userInfoEndpoint()
            .oidcUserService(userService)
            .userService((OAuth2UserService) userService)
        .and()
            .tokenEndpoint().accessTokenResponseClient(oAuth2AccessTokenResponseClient);
        // @formatter:on

        // This way of calling allows using a Configurer different from OAuth2ResourceServerConfigurer (tp)
        oauth2ResourceServer(http)
            .jwt()
            .jwtAuthenticationConverter(jwtAuthenticationConverter)
            .decoder(jwtDecoder);
    }

    private MultiRealmOAuth2ResourceServerConfigurer<HttpSecurity> oauth2ResourceServer(HttpSecurity httpSecurity)
        throws Exception
    {
        MultiRealmOAuth2ResourceServerConfigurer<HttpSecurity> configurer = getOrApply(httpSecurity,
            new MultiRealmOAuth2ResourceServerConfigurer<>(
                httpSecurity.getSharedObject(ApplicationContext.class)));

        // Bloody HACK, as httpSecurity.postProcess(configurer) is protected (tp)
        // /httpSecurity.postProcess(configurer);
        Method postProcess = null;
        for (Method m : AbstractConfiguredSecurityBuilder.class.getDeclaredMethods()) {
            if ("postProcess".equals(m.getName())) {
                postProcess = m;
                break;
            }
        }
        if (postProcess != null) {
            postProcess.setAccessible(true);
            postProcess.invoke(httpSecurity, configurer);
                } else {
            throw new IllegalStateException();
                    }

        return configurer;
                }

    private <C extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> C getOrApply(
        HttpSecurity httpSecurity, C configurer) throws Exception {
        C existingConfig = (C) httpSecurity.getConfigurer(configurer.getClass());
        if (existingConfig != null) {
            return existingConfig;
        }
        return httpSecurity.apply(configurer);
    }

    /*
    public AuthenticationEntryPoint authenticationEntryPoint() {
        BearerTokenAuthenticationEntryPoint result = new BearerTokenAuthenticationEntryPoint();
        result.setRealmName("my realm");
        return result;
    }
     */

    // @Bean
    @SuppressWarnings("unchecked")
    private GrantedAuthoritiesMapper userAuthoritiesMapper() {
        // Now at io.github.jhipster.registry.config.OAuth2SecurityConfiguration.userAuthoritiesMapper
        return null;
    }

    // @Bean
    private JwtDecoder jwtDecoder() {
        String issuerUri = "dummy-error";
        NimbusJwtDecoderJwkSupport jwtDecoder = (NimbusJwtDecoderJwkSupport)
            JwtDecoders.fromOidcIssuerLocation(issuerUri);

        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator(jHipsterProperties.getSecurity().getOauth2().getAudience());
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
        OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer, audienceValidator);

        jwtDecoder.setJwtValidator(withAudience);

        return jwtDecoder;
    }

    @Bean
    public AuthorizationHeaderFilter authHeaderFilter(AuthorizationHeaderUtil headerUtil) {
        return new AuthorizationHeaderFilter(headerUtil);
    }
}
