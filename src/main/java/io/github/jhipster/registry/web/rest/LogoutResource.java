package io.github.jhipster.registry.web.rest;

import io.github.jhipster.registry.client.keycloak.KeycloakLogoutHandler;
import io.github.jhipster.registry.config.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
* REST controller for managing global OIDC logout.
*/
@RestController
@Profile(Constants.PROFILE_OAUTH2)
public class LogoutResource {

    private static final Logger LOG = LoggerFactory.getLogger(LogoutResource.class);

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final KeycloakLogoutHandler keycloakLogoutHandler;
    private final OAuth2AuthorizedClientService clientService;

    private ClientHttpRequestFactory clientHttpRequestFactory;
    private ClientRegistration registration;

    public LogoutResource(
        @Autowired(required = false) ClientRegistrationRepository registrations,
        @Autowired(required = false) OAuth2AuthorizedClientService clientService,
        @Autowired(required = false) KeycloakLogoutHandler keycloakLogoutHandler,
        @Autowired(required = false) ClientHttpRequestFactory clientHttpRequestFactory
    ) {
        if (registrations != null) {
            // TODO tp: was "oidc"
            this.registration = registrations.findByRegistrationId("kcqs");
        }
        this.clientRegistrationRepository = registrations;
        this.clientService = clientService;
        this.keycloakLogoutHandler = keycloakLogoutHandler;
        this.clientHttpRequestFactory = clientHttpRequestFactory;
    }

    @PostConstruct
    void init() {
        if (clientHttpRequestFactory == null) {
            clientHttpRequestFactory = new SimpleClientHttpRequestFactory();
        }
    }

    /**
     * {@code POST  /api/logout} : logout the current user.
     *
     * @param request the {@link HttpServletRequest}.
     * @param idToken the ID token.
     * @return the {@link ResponseEntity} with status {@code 200 (OK)} and a body with a global logout URL and ID token.
     */
    @PostMapping("/api/logout")
    public ResponseEntity<?> logout(HttpServletRequest request,
        HttpServletResponse response,
        Authentication authentication, HttpSession session,
        @AuthenticationPrincipal(expression = "idToken") OidcIdToken idToken
    ) throws IOException {
        if (keycloakLogoutHandler != null) {
            return keycloakLogout(request, response, authentication, session);
        } else {
            String logoutUrl = this.registration.getProviderDetails()
                .getConfigurationMetadata().get("end_session_endpoint").toString();
            Map<String, String> logoutDetails = new HashMap<>();
            logoutDetails.put("logoutUrl", logoutUrl);
            logoutDetails.put("idToken", idToken.getTokenValue());
            request.getSession().invalidate();
            return ResponseEntity.ok().body(logoutDetails);
        }
    }

    private ResponseEntity<Map<String, String>> keycloakLogout(
        HttpServletRequest request, HttpServletResponse response, Authentication authentication, HttpSession session
    ) throws IOException {

        final OAuth2AuthorizedClient client;
        final ClientRegistration registration;

        // TODO: logout with other types of Authentication
        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            String name = oauthToken.getName();
            String registrationId = oauthToken.getAuthorizedClientRegistrationId();
            registration = clientRegistrationRepository.findByRegistrationId(registrationId);
            client = clientService.loadAuthorizedClient(registrationId, name);

            clientService.removeAuthorizedClient(registrationId, name);
            oauthToken.setAuthenticated(false);
        } else {
            LOG.warn("Unexpected token type: " + authentication);
            registration = null;
            client = null;
        }

        Map<String, String> logoutDetails = new HashMap<>();
        if (registration != null) {
            Map<String, Object> metadata = registration.getProviderDetails().getConfigurationMetadata();
            if (metadata != null) {
                Object endPoint = metadata.get("end_session_endpoint");
                if (endPoint != null) {
                    logoutDetails.put("logoutUrl", endPoint.toString());
                }
            }
        }
        keycloakLogoutHandler.logout(request, response, authentication);

        return ResponseEntity.ok().body(logoutDetails);
    }

}
