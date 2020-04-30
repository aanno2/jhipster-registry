package io.github.jhipster.registry.client.keycloak;

import com.google.common.base.MoreObjects;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.SessionScope;

@Component
@SessionScope(proxyMode = ScopedProxyMode.TARGET_CLASS)
public class TokenSessionStore {

    private OAuth2AccessToken accessToken;

    private OAuth2RefreshToken refreshToken;

    public TokenSessionStore() {
    }

    void setOAuth2AccessTokenResponse(OAuth2AccessTokenResponse accessTokenResponse) {
        if (accessTokenResponse == null) {
            accessToken = null;
            refreshToken = null;
        } else {
            accessToken = accessTokenResponse.getAccessToken();
            refreshToken = accessTokenResponse.getRefreshToken();
        }
    }

    public OAuth2AccessToken getAccessToken() {
        return accessToken;
    }

    public OAuth2RefreshToken getRefreshToken() {
        return refreshToken;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
            .add("accessToken", accessToken)
            .add("refreshToken", refreshToken)
            .toString();
    }
}
