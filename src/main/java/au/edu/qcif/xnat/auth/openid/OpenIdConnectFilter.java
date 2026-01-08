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

import au.edu.qcif.xnat.auth.openid.tokens.OpenIdAuthRequestToken;
import au.edu.qcif.xnat.auth.openid.tokens.OpenIdAuthToken;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

import org.apache.commons.collections.ListUtils;
import org.apache.commons.lang3.StringUtils;
import org.nrg.framework.generics.GenericUtils;
import org.nrg.xdat.entities.XdatUserAuth;
import org.nrg.xdat.exceptions.UsernameAuthMappingNotFoundException;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.security.helpers.UserHelper;
import org.nrg.xdat.security.helpers.Users;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xdat.turbine.utils.AccessLogger;
import org.nrg.xdat.turbine.utils.TurbineUtils;
import org.nrg.xft.event.EventDetails;
import org.nrg.xft.event.EventUtils;
import org.nrg.xft.security.UserI;
import org.nrg.xnat.security.exceptions.NewAutoAccountNotAutoEnabledException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.nrg.xdat.services.XdatUserAuthService.OPENID;

/**
 * Main Spring Security authentication filter.
 *
 * @author <a href="https://github.com/shilob">Shilo Banihit</a>
 */
@SuppressWarnings("deprecation")
@EnableOAuth2Client
@Slf4j
public class OpenIdConnectFilter extends AbstractAuthenticationProcessingFilter {
    private static final List<String> ALL_DOMAINS = Collections.singletonList("*");
    private static final String CONFIG_REGEX_FILTER_PREFIX = "regexFilter.";

    private final OpenIdAuthPlugin             _plugin;
    private final AuthenticationEventPublisher _eventPublisher;
    private final XdatUserAuthService          _userAuthService;
    private final SiteConfigPreferences        _siteConfigPreferences;
    private final Map<String, List<String>>    _allowedDomains;
    private final ObjectMapper                 _objectMapper;

    private OAuth2RestTemplate _restTemplate;

    public OpenIdConnectFilter(final String defaultFilterProcessesUrl, final OpenIdAuthPlugin plugin, final AuthenticationEventPublisher eventPublisher, final XdatUserAuthService userAuthService, final SiteConfigPreferences siteConfigPreferences) {
        super(defaultFilterProcessesUrl);
        log.debug("Creating filter for URL {}", defaultFilterProcessesUrl);
        setAuthenticationManager(new NoopAuthenticationManager());
        _plugin                = plugin;
        _eventPublisher        = eventPublisher;
        _userAuthService       = userAuthService;
        _siteConfigPreferences = siteConfigPreferences;

        _allowedDomains = _plugin.getEnabledProviders().stream().collect(Collectors.toMap(Function.identity(), this::getAllowedEmailDomains));
        // TODO: This should be initialized from or replaced by the SerializerService instance
        _objectMapper = new ObjectMapper();
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

    @Autowired
    public void setOAuth2RestTemplate(final OAuth2RestTemplate restTemplate) {
        _restTemplate = restTemplate;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        log.debug("Executed attemptAuthentication...");

        HttpSession session = request.getSession(false);
        if (session != null) {
            String requestProviderId = request.getParameter("providerId");
            String sessionProviderId = (String) request.getSession().getAttribute("providerId");
            if (requestProviderId != null && !requestProviderId.equals(sessionProviderId)) {
                log.debug("Found a session that had previously stopped during the OAuth/OIDC authentication process. Deleting the session.");
                request.getSession().invalidate();
            }
        }

        OAuth2AccessToken accessToken;
        try {
            log.debug("Getting access token...");
            accessToken = _restTemplate.getAccessToken();
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

        log.debug("Getting idToken...");
        final String idToken      = accessToken.getAdditionalInformation().get("id_token").toString();
        final Jwt    tokenDecoded = JwtHelper.decode(idToken);

        log.debug("===== : {}", tokenDecoded.getClaims());
        final Map<String, String> authInfo = GenericUtils.convertToTypedMap(_objectMapper.readValue(tokenDecoded.getClaims(), Map.class), String.class, String.class);

        final String userInfoUri = _plugin.getProperty(providerId, "userInfoUri");
        if (!StringUtils.isEmpty(userInfoUri)) {
            log.debug("Getting User Info from {} using token {}", userInfoUri, accessToken.getValue());
            Map<String, String> userInfo = getUserInfo(accessToken.getValue(), userInfoUri);
            for (String key : userInfo.keySet()) {
                log.debug("User Info: {} = {}", key, userInfo.get(key));
            }
            authInfo.putAll(userInfo);
        }
        final OpenIdConnectUserDetails user = new OpenIdConnectUserDetails(providerId, authInfo, accessToken, _plugin);

        if (shouldFilterEmailDomains(providerId) && !isAllowedEmailDomain(user.getEmail(), providerId)) {
            throw new NewAutoAccountNotAutoEnabledException("New OpenID user, email is not on the domain whitelist.", user);
        }
        if (!_plugin.isEnabled(providerId)) {
            throw new NewAutoAccountNotAutoEnabledException("OpenID provider is not enabled", user);
        }
        if (!passesRegexFilters(authInfo, providerId)) {
            throw new NewAutoAccountNotAutoEnabledException("New OpenID user, did not pass regex filters.", user);
        }

        log.debug("Checking if user exists...");
        UserI  xdatUser;
        String requesterUsername = null;
        try {
            requesterUsername = user.getUsername();
            xdatUser          = _userAuthService.getUserDetailsByNameAndAuth(requesterUsername, XdatUserAuthService.OPENID, providerId);
            if (!xdatUser.isEnabled()) {
                throw new NewAutoAccountNotAutoEnabledException("New OpenID user, needs to to be enabled.", xdatUser);
            }
            if ((getSiteConfigPreferences().getEmailVerification() && !xdatUser.isVerified()) || !xdatUser.isAccountNonLocked()) {
                throw new CredentialsExpiredException("Attempted login to unverified or locked account: " + xdatUser.getUsername());
            }
        } catch (UsernameAuthMappingNotFoundException e) {
            if (Boolean.parseBoolean(_plugin.getProperty(providerId, "forceUserCreate"))) {
                xdatUser = createUserAccount(providerId, user);
            } else {
                // Give users an option to connect OpenID Account with an XNAT account
                log.info("User {} attempted to log using authentication provider ID {}, diverting to account merge page.", user.getUsername(), providerId);
                request.getSession().setAttribute(UsernameAuthMappingNotFoundException.class.getSimpleName(), new UsernameAuthMappingNotFoundException(e.getUsername(), e.getAuthMethod(), e.getAuthMethodId(), user.getEmail(), user.getLastname(), user.getFirstname()));
                response.sendRedirect(TurbineUtils.GetFullServerPath() + "/app/template/RegisterExternalLogin.vm");
                return null;
            }
        }

        if (requesterUsername != null) {
            Authentication authentication = new OpenIdAuthToken(xdatUser, providerId);

            Authentication authRequestToken = new OpenIdAuthRequestToken(requesterUsername, providerId);
            _eventPublisher.publishAuthenticationSuccess(authRequestToken);

            org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(authRequestToken);
            AccessLogger.LogServiceAccess(xdatUser.getUsername(), request, "Authentication", "SUCCESS");
            UserHelper.setUserHelper(request, user);

            return authentication;
        }
        return null;
    }

    private UserI createUserAccount(final String providerId, final OpenIdConnectUserDetails user) throws AuthenticationException {
        String userAutoEnabled  = _plugin.getProperty(providerId, "userAutoEnabled");
        String userAutoVerified = _plugin.getProperty(providerId, "userAutoVerified");

        UserI xdatUser = Users.createUser();
        xdatUser.setLogin(user.getUsername().replace("|", "_"));
        xdatUser.setFirstname(user.getFirstname());
        xdatUser.setLastname(user.getLastname());
        xdatUser.setEmail(user.getEmail());
        xdatUser.setEnabled(userAutoEnabled);
        xdatUser.setVerified(userAutoVerified);

        log.info("Create user, username: {}", xdatUser.getUsername());
        try {
            UserI adminUser = Users.getAdminUser();
            Users.save(xdatUser, adminUser,
                       new XdatUserAuth(user.getUsername(), XdatUserAuthService.OPENID, providerId, xdatUser.getLogin(), true, 0),
                       false, new EventDetails(EventUtils.CATEGORY.DATA, EventUtils.TYPE.WEB_SERVICE,
                                               "Added User", "Requested by user " + adminUser.getUsername(),
                                               "Created new user " + user.getUsername() + " through OpenID connect."));
        } catch (Exception ex2) {
            log.warn("Ignoring exception:", ex2);
        }
        return xdatUser;
    }

    /**
     * Checks whether the user info passes all regex filters defined in the plugin configuration for the given provider.
     */
    private boolean passesRegexFilters(final Map<String, String> userInfo, final String providerId) {
        Properties props = _plugin.getProps();
        String prefix = String.join(".", OPENID, providerId, CONFIG_REGEX_FILTER_PREFIX);
        for (Map.Entry<Object, Object> entry : props.entrySet()) {
            Object objKey = entry.getKey();
            if (objKey instanceof String) {
                String key = (String) objKey;
                if (key.startsWith(prefix)) {
                    Object objValue = entry.getValue();
                    if (objValue instanceof String) {
                        String value = (String) objValue;
                        log.debug("Applying regex filter {} = {} for provider {}", key, value, providerId);
                        String fieldName = key.substring(prefix.length());
                        String fieldValue = userInfo.get(fieldName);
                        if (fieldValue == null || !fieldValue.matches(value)) {
                            log.error("User info field {} with value {} did not pass regex filter {} for provider {}", fieldName, fieldValue, value, providerId);
                            return false;
                        }
                    }
                }
            }
        }
        return true;
    }

    private boolean shouldFilterEmailDomains(final String providerId) {
        return  Boolean.parseBoolean(StringUtils.defaultIfBlank(_plugin.getProperty(providerId, "shouldFilterEmailDomains"), "false"));
    }

    private List<String> getAllowedEmailDomains(final String providerId) {
        return shouldFilterEmailDomains(providerId)
               ? Arrays.stream(_plugin.getProperty(providerId, "allowedEmailDomains").split("\\s*,\\s*"))
                       .map(StringUtils::lowerCase)
                       .collect(Collectors.toList())
               : ALL_DOMAINS;
    }

    private boolean isAllowedEmailDomain(final String email, final String providerId) {
        if (!_allowedDomains.containsKey(providerId)) {
            return false;
        }
        if (!shouldFilterEmailDomains(providerId)) {
            return true;
        }
        final List<String> allowedDomains = _allowedDomains.get(providerId);
        if (ListUtils.isEqualList(ALL_DOMAINS, allowedDomains)) {
            return true;
        }
        final String[] emailParts = email.split("@");
        final String   domain     = emailParts.length >= 2 ? emailParts[1] : null;
        if (StringUtils.isBlank(domain)) {
            log.warn("Couldn't parse a domain from the email address {}, returning false", email);
            return false;
        }
        if (allowedDomains.contains(StringUtils.lowerCase(domain))) {
            log.debug("Matched email {} with allowed domain {} for provider {}", email, _allowedDomains, providerId);
            return true;
        }
        log.debug("Email {} did not match any allowed domains for provider {}: {}", email, providerId, StringUtils.join(_allowedDomains, ", "));
        return false;
    }

    protected SiteConfigPreferences getSiteConfigPreferences() {
        return _siteConfigPreferences;
    }

    private Map<String, String> getUserInfo(final String accessToken, final String userInfoEndpoint) {
        // See https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        return GenericUtils.convertToTypedMap(_restTemplate.exchange(userInfoEndpoint, HttpMethod.GET, new HttpEntity<>(headers), Map.class).getBody(), String.class, String.class);
    }

    private static class NoopAuthenticationManager implements AuthenticationManager {
        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            throw new UnsupportedOperationException("No authentication should be done with this AuthenticationManager");
        }
    }
}
