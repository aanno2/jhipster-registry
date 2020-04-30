package io.github.jhipster.registry.security.oauth2;

import io.github.jhipster.registry.config.AdditionalIssuersForResourceServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;

/**
 * As OAuth2ResourceServerConfigurer is final, I copyied and modified it.
 *
 * @param <H>
 * @author ThomasPasch@acm.siteos.de
 */
public class MultiRealmOAuth2ResourceServerConfigurer<H extends HttpSecurityBuilder<H>> extends
    AbstractHttpConfigurer<MultiRealmOAuth2ResourceServerConfigurer<H>, H> {

    private static final Logger LOG = LoggerFactory.getLogger(MultiRealmOAuth2ResourceServerConfigurer.class);

    private final ApplicationContext context;
    private final AdditionalIssuersForResourceServer additionalIssuersForResourceServer;

    private BearerTokenResolver bearerTokenResolver;
    private MultiRealmOAuth2ResourceServerConfigurer.JwtConfigurer jwtConfigurer;

    private AccessDeniedHandler accessDeniedHandler = new BearerTokenAccessDeniedHandler();
    private AuthenticationEntryPoint authenticationEntryPoint = new BearerTokenAuthenticationEntryPoint();
    private MultiRealmOAuth2ResourceServerConfigurer.BearerTokenRequestMatcher requestMatcher =
        new MultiRealmOAuth2ResourceServerConfigurer.BearerTokenRequestMatcher();

    public MultiRealmOAuth2ResourceServerConfigurer(ApplicationContext context) {
        Assert.notNull(context, "context cannot be null");
        this.context = context;
        this.additionalIssuersForResourceServer = this.context.getBean(AdditionalIssuersForResourceServer.class);
    }

    public MultiRealmOAuth2ResourceServerConfigurer<H> accessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
        Assert.notNull(accessDeniedHandler, "accessDeniedHandler cannot be null");
        this.accessDeniedHandler = accessDeniedHandler;
        return this;
    }

    public MultiRealmOAuth2ResourceServerConfigurer<H> authenticationEntryPoint(AuthenticationEntryPoint entryPoint) {
        Assert.notNull(entryPoint, "entryPoint cannot be null");
        this.authenticationEntryPoint = entryPoint;
        return this;
    }

    public MultiRealmOAuth2ResourceServerConfigurer<H> bearerTokenResolver(BearerTokenResolver bearerTokenResolver) {
        Assert.notNull(bearerTokenResolver, "bearerTokenResolver cannot be null");
        this.bearerTokenResolver = bearerTokenResolver;
        return this;
    }

    public MultiRealmOAuth2ResourceServerConfigurer.JwtConfigurer jwt() {
        if (this.jwtConfigurer == null) {
            this.jwtConfigurer = new MultiRealmOAuth2ResourceServerConfigurer.JwtConfigurer(this.context);
        }

        return this.jwtConfigurer;
    }

    @Override
    public void init(H http) throws Exception {
        registerDefaultAccessDeniedHandler(http);
        registerDefaultEntryPoint(http);
        registerDefaultCsrfOverride(http);
    }

    @Override
    public void configure(H http) throws Exception {
        BearerTokenResolver bearerTokenResolver = getBearerTokenResolver();
        this.requestMatcher.setBearerTokenResolver(bearerTokenResolver);

        AuthenticationManager manager = http.getSharedObject(AuthenticationManager.class);

        BearerTokenAuthenticationFilter filter =
            new BearerTokenAuthenticationFilter(manager);
        filter.setBearerTokenResolver(bearerTokenResolver);
        filter.setAuthenticationEntryPoint(this.authenticationEntryPoint);
        filter = postProcess(filter);

        http.addFilter(filter);

        if (this.jwtConfigurer == null) {
            throw new IllegalStateException("Jwt is the only supported format for bearer tokens " +
                "in Spring Security and no Jwt configuration was found. Make sure to specify " +
                "a jwk set uri by doing http.oauth2ResourceServer().jwt().jwkSetUri(uri), or wire a " +
                "JwtDecoder instance by doing http.oauth2ResourceServer().jwt().decoder(decoder), or " +
                "expose a JwtDecoder instance as a bean and do http.oauth2ResourceServer().jwt().");
        }

        JwtDecoder decoder = this.jwtConfigurer.getJwtDecoder();
        Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter =
            this.jwtConfigurer.getJwtAuthenticationConverter();

        // This code is the only difference to OAuth2ResourceServerConfigurer (tp)
        JwtAuthenticationProvider provider =
            new JwtAuthenticationProvider(decoder);
        provider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
        provider = postProcess(provider);

        http.authenticationProvider(new StoringAuthenticationProviderProxy(provider));

        if (additionalIssuersForResourceServer.getIssuerUris() == null
            || additionalIssuersForResourceServer.getIssuerUris().isEmpty()) {
            throw new IllegalStateException();
        }
        LOG.info("jwtDecoders: " + additionalIssuersForResourceServer.getIssuerUris() + " "
            + additionalIssuersForResourceServer.additionalJwtDecoders());
        for (JwtDecoder jd : additionalIssuersForResourceServer.additionalJwtDecoders()) {
            JwtAuthenticationProvider p =
                new JwtAuthenticationProvider(jd);
            p.setJwtAuthenticationConverter(jwtAuthenticationConverter);
            p = postProcess(p);
            http.authenticationProvider(new StoringAuthenticationProviderProxy(p));
        }
    }

    public class JwtConfigurer {
        private final ApplicationContext context;

        private JwtDecoder decoder;

        private Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter =
            new JwtAuthenticationConverter();

        JwtConfigurer(ApplicationContext context) {
            this.context = context;
        }

        public MultiRealmOAuth2ResourceServerConfigurer.JwtConfigurer decoder(JwtDecoder decoder) {
            this.decoder = decoder;
            return this;
        }

        public MultiRealmOAuth2ResourceServerConfigurer.JwtConfigurer jwkSetUri(String uri) {
            this.decoder = new NimbusJwtDecoderJwkSupport(uri);
            return this;
        }

        public MultiRealmOAuth2ResourceServerConfigurer.JwtConfigurer jwtAuthenticationConverter
            (Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter) {

            this.jwtAuthenticationConverter = jwtAuthenticationConverter;
            return this;
        }

        public MultiRealmOAuth2ResourceServerConfigurer<H> and() {
            return MultiRealmOAuth2ResourceServerConfigurer.this;
        }

        Converter<Jwt, ? extends AbstractAuthenticationToken> getJwtAuthenticationConverter() {
            return this.jwtAuthenticationConverter;
        }

        JwtDecoder getJwtDecoder() {
            if (this.decoder == null) {
                return this.context.getBean(JwtDecoder.class);
            }

            return this.decoder;
        }
    }

    private void registerDefaultAccessDeniedHandler(H http) {
        ExceptionHandlingConfigurer<H> exceptionHandling = http
            .getConfigurer(ExceptionHandlingConfigurer.class);
        if (exceptionHandling == null) {
            return;
        }

        exceptionHandling.defaultAccessDeniedHandlerFor(
            this.accessDeniedHandler,
            this.requestMatcher);
    }

    private void registerDefaultEntryPoint(H http) {
        ExceptionHandlingConfigurer<H> exceptionHandling = http
            .getConfigurer(ExceptionHandlingConfigurer.class);
        if (exceptionHandling == null) {
            return;
        }

        exceptionHandling.defaultAuthenticationEntryPointFor(
            this.authenticationEntryPoint,
            this.requestMatcher);
    }

    private void registerDefaultCsrfOverride(H http) {
        CsrfConfigurer<H> csrf = http
            .getConfigurer(CsrfConfigurer.class);
        if (csrf == null) {
            return;
        }

        csrf.ignoringRequestMatchers(this.requestMatcher);
    }

    BearerTokenResolver getBearerTokenResolver() {
        if (this.bearerTokenResolver == null) {
            if (this.context.getBeanNamesForType(BearerTokenResolver.class).length > 0) {
                this.bearerTokenResolver = this.context.getBean(BearerTokenResolver.class);
            } else {
                this.bearerTokenResolver = new DefaultBearerTokenResolver();
            }
        }

        return this.bearerTokenResolver;
    }

    private static final class BearerTokenRequestMatcher implements RequestMatcher {
        private BearerTokenResolver bearerTokenResolver;

        @Override
        public boolean matches(HttpServletRequest request) {
            try {
                return this.bearerTokenResolver.resolve(request) != null;
            } catch (OAuth2AuthenticationException e) {
                return false;
            }
        }

        public void setBearerTokenResolver(BearerTokenResolver tokenResolver) {
            Assert.notNull(tokenResolver, "resolver cannot be null");
            this.bearerTokenResolver = tokenResolver;
        }
    }
}
