package io.github.jhipster.registry.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "spring.security.oauth2.additional.jwt")
@Profile(Constants.PROFILE_OAUTH2)
public class AdditionalIssuersForResourceServer {

    private List<String> issuerUris;
    private List<JwtDecoder> additionalJwtDecoders;

    public AdditionalIssuersForResourceServer() {
    }

    public List<JwtDecoder> additionalJwtDecoders() {
        if (additionalJwtDecoders == null) {
            additionalJwtDecoders = new ArrayList<>();
            for (String issuer : issuerUris) {
                // This will use certs from main oidc (wrong) (tp)
                // additionalJwtDecoders.add(JwtDecoders.fromOidcIssuerLocation(issuer));

                // This seems to be keycloak specific (tp)
                String certs = issuer + "/protocol/openid-connect/certs";
                JwtDecoder jwtDecoder = new NimbusJwtDecoderJwkSupport(certs);
                additionalJwtDecoders.add(jwtDecoder);
            }
        }
        return additionalJwtDecoders;
    }

    public List<String> getIssuerUris() {
        return issuerUris;
    }

    public void setIssuerUris(List<String> issuerUris) {
        this.issuerUris = issuerUris;
        this.additionalJwtDecoders = null;
    }
}
