package io.github.jhipster.registry.config;

import de.codecentric.boot.admin.server.domain.entities.Instance;
import de.codecentric.boot.admin.server.domain.values.Endpoint;
import de.codecentric.boot.admin.server.domain.values.Registration;
import de.codecentric.boot.admin.server.services.EndpointDetector;
import de.codecentric.boot.admin.server.services.InstanceRegistry;
import de.codecentric.boot.admin.server.web.client.HttpHeadersProvider;
import io.github.jhipster.registry.client.keycloak.TokenSessionStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.util.function.Function;
import java.util.function.ToIntFunction;
import java.util.stream.Collectors;

@Configuration
public class SpringBootAdminConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(SpringBootAdminConfiguration.class);

    public static final String AUTHORIZATION_HEADER = "Authorization";

    public static final String BEARER_TOKEN_TYPE = "Bearer";

    private static final Integer ONE = Integer.valueOf(1);

    private static final ToIntFunction<Object> ONE_FUNC = new ToIntFunction<Object>() {
        @Override
        public int applyAsInt(Object value) {
            return 1;
        }
    };

    // HACK tp
    private OAuth2AccessToken lastAccessToken;

    @Bean
    public HttpHeadersProvider bearerHttpHeadersProvider(
        @Lazy InstanceRegistry registry, @Lazy EndpointDetector detector, TokenSessionStore tokenSessionStore)
    {
        return new HttpHeadersProvider() {
            @Override
            public HttpHeaders getHeaders(Instance instance) {
                HttpHeaders result = new HttpHeaders();
                SecurityContext ctx = SecurityContextHolder.getContext();
                if (ctx != null) {
                    Authentication auth = ctx.getAuthentication();
                    if (auth != null) {
                        try {
                            lastAccessToken = tokenSessionStore.getAccessToken();
                            result.add(AUTHORIZATION_HEADER, String.format("%s %s", BEARER_TOKEN_TYPE, lastAccessToken.getTokenValue()));

                            /* does not work (tp)
                            registry.getInstances().map(i -> {
                                Registration r = i.getRegistration();
                                return registry.deregister(i.getId())
                                    .flatMap(id -> registry.register(r))
                                    .map(id -> detector.detectEndpoints(id));
                            });
                             */
                        } catch (BeanCreationException e) {
                            // TODO tp: Is there a better way to find out if we are in session scope?
                            // do nothing
                        }
                    }
                }
                final int size = result.size();
                if (size == 0 && lastAccessToken != null) {
                    // HACK tp: We have protected the admin ui, but the registered instance monitoring will be in
                    // intervals. Hence sometimes we don't get a bearer token. This is a petty and we
                    // circumvent that here...
                    result.add(AUTHORIZATION_HEADER, String.format("%s %s", BEARER_TOKEN_TYPE, lastAccessToken.getTokenValue()));
                }
                if (size > 0) {
                    LOG.debug("new headers (bearer token): " + size);
                }
                return result;
            }
        };
    }
}
