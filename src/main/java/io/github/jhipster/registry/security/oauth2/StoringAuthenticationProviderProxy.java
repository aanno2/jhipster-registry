package io.github.jhipster.registry.security.oauth2;

import com.google.common.collect.MapMaker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;

import java.util.Optional;
import java.util.concurrent.ConcurrentMap;

public class StoringAuthenticationProviderProxy implements AuthenticationProvider {

    private static final ConcurrentMap<Authentication, BearerTokenAuthenticationToken> AUTH2TOKEN = new MapMaker()
        .concurrencyLevel(4)
        .weakKeys()
        .makeMap();

    private final AuthenticationProvider wrapped;

    public StoringAuthenticationProviderProxy(AuthenticationProvider wrapped) {
        this.wrapped = wrapped;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        BearerTokenAuthenticationToken bearer = null;
        if (authentication instanceof BearerTokenAuthenticationToken) {
            bearer = (BearerTokenAuthenticationToken) authentication;
        }
        Authentication result =  wrapped.authenticate(authentication);
        if (bearer != null) {
            AUTH2TOKEN.put(result, bearer);
        }
        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return wrapped.supports(authentication);
    }

    public static Optional<String> getTokenFor(Authentication authentication) {
        BearerTokenAuthenticationToken result = AUTH2TOKEN.get(authentication);
        if (result == null) {
            return Optional.empty();
        }
        return Optional.of(result.getToken());
    }
}
