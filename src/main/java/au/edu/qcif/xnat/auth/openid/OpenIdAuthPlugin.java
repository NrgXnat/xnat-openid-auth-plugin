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

import java.util.*;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.nrg.framework.annotations.XnatPlugin;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xnat.security.BaseXnatSecurityExtension;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;
import org.nrg.xnat.security.provider.ProviderAttributes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import au.edu.qcif.xnat.auth.openid.pkce.PkceAuthorizationCodeAccessTokenProvider;
import au.edu.qcif.xnat.auth.openid.pkce.PkceAuthorizationCodeResourceDetails;
import lombok.extern.slf4j.Slf4j;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.PKCE_ENABLED;
import static org.nrg.xdat.services.XdatUserAuthService.OPENID;

/**
 * XNAT Authentication plugin.
 *
 * @author <a href="https://github.com/shilob">Shilo Banihit</a>
 */
@SuppressWarnings("deprecation")
@XnatPlugin(value = "openIdAuthPlugin", name = "XNAT OpenID Authentication Provider Plugin", logConfigurationFile = "au/edu/qcif/xnat/auth/openid/openid-auth-plugin-logback.xml")
@EnableWebSecurity
@EnableOAuth2Client
@Component
@ComponentScan("au.edu.qcif.xnat.auth.openid.provider")
@Slf4j
public class OpenIdAuthPlugin extends BaseXnatSecurityExtension {
    private static final AccessTokenProvider ACCESS_TOKEN_PROVIDER_CHAIN = new AccessTokenProviderChain(
            Arrays.<AccessTokenProvider>asList(new PkceAuthorizationCodeAccessTokenProvider(),
                                               new ImplicitAccessTokenProvider(),
                                               new ResourceOwnerPasswordAccessTokenProvider(),
                                               new ClientCredentialsAccessTokenProvider()));

    private final AuthenticationEventPublisher               _eventPublisher;
    private final XdatUserAuthService                        _userAuthService;
    private final AuthenticationProviderConfigurationLocator _locator;
    private final SiteConfigPreferences                      _siteConfigPreferences;
    private final Properties                                 _props = new Properties();
    private final List<String>                     _openIdProviders = new ArrayList<>();

    @Autowired
    public OpenIdAuthPlugin(final AuthenticationEventPublisher eventPublisher, final XdatUserAuthService userAuthService, final AuthenticationProviderConfigurationLocator locator, final SiteConfigPreferences siteConfigPreferences) {
        _eventPublisher        = eventPublisher;
        _userAuthService       = userAuthService;
        _locator               = locator;
        _siteConfigPreferences = siteConfigPreferences;
        setup();
    }

    public boolean isEnabled(final String providerId) {
        return _openIdProviders.contains(providerId);
    }

    public String getProperty(String providerId, String propName) {
        return _props.getProperty(String.join(".", OPENID, providerId, propName));
    }

    public Properties getProps() {
        return _props;
    }

    public List<String> getEnabledProviders() {
        return _openIdProviders;
    }

    @Bean
    @Scope("prototype")
    public OpenIdConnectFilter createFilter() {
        return new OpenIdConnectFilter(getProps().getProperty("preEstablishedRedirUri"), this, _eventPublisher, _userAuthService, _siteConfigPreferences);
    }

    @Override
    public void configure(final HttpSecurity http) {
        try {
            if (!_props.isEmpty()) {
                http.addFilterAfter(new OAuth2ClientContextFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                    .addFilterAfter(createFilter(), OAuth2ClientContextFilter.class);
            }
        } catch (Throwable e) {
            log.error("An error occurred trying to create and/or configure the OAuth2ClientContextFilter and OpenIdConnectFilter", e);
        }
    }

    public String getAuthMethod() {
        return OPENID;
    }

    @Bean
    @Scope(value = WebApplicationContext.SCOPE_SESSION, proxyMode = ScopedProxyMode.TARGET_CLASS)
    public OAuth2RestTemplate restTemplate(final OAuth2ClientContext clientContext) {
        log.debug("At create rest template...");
        final HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        // Interrogate request to get providerId (e.g. look at url if nothing
        // else)
        String providerId = (String) request.getSession().getAttribute("providerId");
        log.debug("Provider id is: {}", providerId);
        final OAuth2RestTemplate template = new OAuth2RestTemplate(getProtectedResourceDetails(providerId), clientContext);
        template.setAccessTokenProvider(ACCESS_TOKEN_PROVIDER_CHAIN);
        return template;
    }

    public AuthorizationCodeResourceDetails getProtectedResourceDetails(final String providerId) {
        log.debug("Creating protected resource details of provider: {}", providerId);
        final String clientId       = getProperty(providerId, "clientId");
        final String clientSecret   = getProperty(providerId, "clientSecret");
        final String accessTokenUri = getProperty(providerId, "accessTokenUri");
        final String userAuthUri    = getProperty(providerId, "userAuthUri");
        final String preEstablishedUri = StringUtils.getIfBlank(getProps().getProperty("siteUrl"), _siteConfigPreferences::getSiteUrl)
                                         + StringUtils.prependIfMissing(getProps().getProperty("preEstablishedRedirUri"), "/");
        final List<String> scopes = Arrays.asList(StringUtils.split(getProperty(providerId, "scopes"), ", "));

        final PkceAuthorizationCodeResourceDetails details = new PkceAuthorizationCodeResourceDetails();
        details.setClientId(clientId);
        details.setClientSecret(clientSecret);
        details.setAccessTokenUri(accessTokenUri);
        details.setUserAuthorizationUri(userAuthUri);
        details.setScope(scopes);
        details.setPreEstablishedRedirectUri(preEstablishedUri);
        details.setUseCurrentUri(false);
        details.setPkceEnabled(isPkceEnabled(providerId));
        return details;
    }

    private boolean isPkceEnabled(final String providerId) {
        final boolean pkceEnabled = Boolean.parseBoolean(getProperty(providerId, PKCE_ENABLED));
        log.debug("Is PKCE Enabled: {}", pkceEnabled);
        return pkceEnabled;
    }

    private void setup() {
        final Map<String, ProviderAttributes> openIdProviders = _locator.getProviderDefinitionsByAuthMethod("openid");
        if (openIdProviders.size() == 0) {
            log.error("There are no OpenID providers configured");
        } else {
            //Collate properties across all property definitions to facilitate multiple open id prop file
           openIdProviders.forEach((providerId, v)  -> {
               _openIdProviders.add(providerId);
               final ProviderAttributes providerDefinition = _locator.getProviderDefinition(providerId);
               if (providerDefinition != null) {
                   _props.putAll(providerDefinition.getProperties());
               } else {
                   log.error("I can't find the provider definition for that ID: {}", providerId);
               }
           });
           if (_props.isEmpty()) {
               log.error("Could not set properties for available providers. Check the auth property files");
           }
           return;
        }
    }

}
