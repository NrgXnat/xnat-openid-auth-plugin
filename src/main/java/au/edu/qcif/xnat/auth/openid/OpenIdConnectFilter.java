/*
 *Copyright (C) 2018 Queensland Cyber Infrastructure Foundation (http://www.qcif.edu.au/)
 *
 *This program is free software: you can redistribute it and/or modify
 *it under the terms of the GNU General Public License as published by
 *the Free Software Foundation; either version 2 of the License, or
 *(at your option) any later version.
 *
 *This program is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 *MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *GNU General Public License for more details.
 *
 *You should have received a copy of the GNU General Public License along
 *with this program; if not, write to the Free Software Foundation, Inc.,
 *51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package au.edu.qcif.xnat.auth.openid;

import java.io.IOException;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import au.edu.qcif.xnat.auth.openid.tokens.OpenIdAuthRequestToken;
import org.apache.commons.lang3.StringUtils;

import org.nrg.xdat.XDAT;
import org.nrg.xdat.exceptions.UsernameAuthMappingNotFoundException;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.security.helpers.Users;
import org.nrg.xdat.security.services.UserManagementServiceI;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xdat.turbine.utils.TurbineUtils;
import org.nrg.xft.security.UserI;
import org.nrg.xnat.security.exceptions.NewAutoAccountNotAutoEnabledException;
import org.springframework.http.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import com.fasterxml.jackson.databind.ObjectMapper;

import au.edu.qcif.xnat.auth.openid.tokens.OpenIdAuthToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.*;

/**
 * Main Spring Security authentication filter.
 *
 * @author <a href='https://github.com/shilob'>Shilo Banihit</a>
 */
@EnableOAuth2Client
@Slf4j
public class OpenIdConnectFilter extends AbstractAuthenticationProcessingFilter {

    private OpenIdAuthPlugin plugin;
    private AuthenticationEventPublisher eventPublisher;
    private XdatUserAuthService userAuthService;

    private String[] allowedDomains;

    @Autowired
    @Qualifier("createRestTemplate")
    private OAuth2RestTemplate restTemplate;

    public OpenIdConnectFilter(
            String defaultFilterProcessesUrl,
            OpenIdAuthPlugin plugin,
            AuthenticationEventPublisher eventPublisher,
            XdatUserAuthService userAuthService
    ) {
        super(defaultFilterProcessesUrl);
        log.debug("Created filter for " + defaultFilterProcessesUrl);
        setAuthenticationManager(new NoopAuthenticationManager());
        // this.providerId = providerId;
        this.plugin = plugin;
        this.eventPublisher = eventPublisher;
        this.userAuthService = userAuthService;
    }

    @Autowired
    @Override
    public void setAuthenticationSuccessHandler(final AuthenticationSuccessHandler handler) {
        super.setAuthenticationSuccessHandler(handler);
    }

    @Autowired
    @Override
    public void setAuthenticationFailureHandler(final AuthenticationFailureHandler handler) {
        super.setAuthenticationFailureHandler(handler);
    }

    @Autowired
    @Override
    public void setSessionAuthenticationStrategy(final SessionAuthenticationStrategy strategy) {
        super.setSessionAuthenticationStrategy(strategy);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        log.debug("Executed attemptAuthentication...");

        HttpSession session = request.getSession(false);
        if (session != null) {
            String requestProviderId = request.getParameter("providerId");
            String sessionProviderId = (String) request.getSession().getAttribute("providerId");
            if (requestProviderId != null && requestProviderId != null && !requestProviderId.equals(sessionProviderId)) {
                log.debug("Found a session that had previously stopped during the OAuth/OIDC authentication process. Deleting the session.");
                request.getSession().invalidate();
            }
        }

        OAuth2AccessToken accessToken;
        try {
            log.debug("Getting access token...");
            accessToken = restTemplate.getAccessToken();
            log.debug("Got access token!!! {}", accessToken);
        } catch (final OAuth2Exception e) {
            log.debug("Could not obtain access token", e);
            log.debug("<<---------------------------->>");
            e.printStackTrace();
            throw new BadCredentialsException("Could not obtain access token", e);
        } catch (final RuntimeException ex2) {
            log.debug("Runtime exception", ex2);
            log.debug("----------------------------");
            throw ex2;
        }
        String providerId = (String) request.getSession().getAttribute("providerId");
        try {
            log.debug("Getting idToken...");
            final String idToken = accessToken.getAdditionalInformation().get("id_token").toString();
            final Jwt tokenDecoded = JwtHelper.decode(idToken);
            log.debug("===== : " + tokenDecoded.getClaims());
            final Map<String, String> authInfo = new ObjectMapper().readValue(tokenDecoded.getClaims(), Map.class);

            String userInfoUri = plugin.getProperty(providerId, "userInfoUri");
            if (!StringUtils.isEmpty(userInfoUri)) {
                Map<String, String> userInfo = this.getUserInfo(accessToken.getValue(), userInfoUri);
                authInfo.putAll(userInfo);
            }

            final OpenIdConnectUserDetails user = new OpenIdConnectUserDetails(providerId, authInfo, accessToken,
                    plugin);

            if (shouldFilterEmailDomains(providerId) && !isAllowedEmailDomain(user.getEmail(), providerId)) {
                log.error("Domain not allowed: " + user.getEmail());

                throw (AuthenticationException) (new NewAutoAccountNotAutoEnabledException(
                        "New OpenID user, not on the domain whitelist.", user));
            }
            if (!plugin.isEnabled(providerId)) {
                log.error("Provider is disabled.");
                throw (AuthenticationException) (new NewAutoAccountNotAutoEnabledException(
                        "OpenID user is not on the enabled list.", user));
            }

            log.debug("Checking if user exists...");
            UserI xdatUser;
            try {
                String requesterUsername = user.getUsername();
                xdatUser = userAuthService.getUserDetailsByNameAndAuth(requesterUsername, XdatUserAuthService.OPENID, providerId);
                if (!xdatUser.isEnabled()) {
                    throw new NewAutoAccountNotAutoEnabledException(
                            "New OpenID user, needs to to be enabled.", xdatUser);
                }
                if ((getSiteConfigPreferences().getEmailVerification() && !xdatUser.isVerified()) || !xdatUser.isAccountNonLocked()) {
                    throw new CredentialsExpiredException("Attempted login to unverified or locked account: " + xdatUser.getUsername());
                }

                Authentication authentication = new OpenIdAuthToken(xdatUser, providerId);

                Authentication authRequestToken = new OpenIdAuthRequestToken(requesterUsername, providerId);
                eventPublisher.publishAuthenticationSuccess(authRequestToken);

                return authentication;
            } catch (UsernameAuthMappingNotFoundException e) {
                log.info("User {} attempted to log using authentication provider ID {}, diverting to account merge page.");

                e = new UsernameAuthMappingNotFoundException(
                        e.getUsername(),
                        e.getAuthMethod(),
                        e.getAuthMethodId(),
                        user.getOpenIdUserInfo(EMAIL),
                        user.getOpenIdUserInfo(GIVEN_NAME),
                        user.getOpenIdUserInfo(FAMILY_NAME)
                );
                request.getSession().setAttribute(UsernameAuthMappingNotFoundException.class.getSimpleName(), e);
                response.sendRedirect(TurbineUtils.GetFullServerPath() + "/app/template/RegisterExternalLogin.vm");
                return null;
            }
        } catch (final InvalidTokenException e) {
            throw new BadCredentialsException("Could not obtain user details from token", e);
        }
    }

    private boolean isAllowedEmailDomain(String email, String providerId) {
        if (allowedDomains == null) {
            allowedDomains = plugin.getProperty(providerId, "allowedEmailDomains").split(",");
        }
        String[] emailParts = email.split("@");
        String domain = emailParts.length >= 2 ? emailParts[1] : null;
        for (String allowedDomain : allowedDomains) {
            if (allowedDomain.equalsIgnoreCase(domain)) {
                log.debug("Matched email {} with allowed domain {} for provider {}", email, allowedDomains, providerId);
                return true;
            }
        }
        log.debug("Email {} did not match any allowed domains for provider {}: {}", email, providerId, StringUtils.join(allowedDomains, ", "));
        return false;
    }

    protected SiteConfigPreferences getSiteConfigPreferences() {
        return XDAT.getSiteConfigPreferences();
    }

    private boolean shouldFilterEmailDomains(String providerId) {
        return Boolean.parseBoolean(plugin.getProperty(providerId, "shouldFilterEmailDomains"));
    }

    private Map<String, String> getUserInfo(String accessToken, String userInfoEndpoint) throws IOException {
        // See https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + accessToken);
        HttpEntity<?> requestEntity = new HttpEntity<>(headers);
        return restTemplate.exchange(userInfoEndpoint, HttpMethod.GET, requestEntity, Map.class).getBody();
    }

    private static class NoopAuthenticationManager implements AuthenticationManager {

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            throw new UnsupportedOperationException("No authentication should be done with this AuthenticationManager");
        }

    }

}
