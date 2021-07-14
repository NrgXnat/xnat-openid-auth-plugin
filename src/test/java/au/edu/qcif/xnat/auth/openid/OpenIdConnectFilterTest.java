package au.edu.qcif.xnat.auth.openid;

import au.edu.qcif.xnat.auth.openid.tokens.OpenIdAuthToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit.WireMockRule;

import org.apache.commons.io.IOUtils;
import org.junit.Rule;
import org.junit.Test;
import org.nrg.framework.configuration.ConfigPaths;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xft.security.UserI;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;

import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static java.nio.charset.Charset.defaultCharset;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OpenIdConnectFilterTest {
    final private OpenIdConnectFilter subject;
    final private ObjectMapper objectMapper = new ObjectMapper();

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(8081);

    final private SiteConfigPreferences siteConfigPreferences = mock(SiteConfigPreferences.class);
    final private AuthenticationEventPublisher eventPublisher = mock(AuthenticationEventPublisher.class);
    final private XdatUserAuthService userAuthService = mock(XdatUserAuthService.class);

    public OpenIdConnectFilterTest() throws IOException {
        System.setProperty("xnat.home", System.getProperty("user.dir"));

        OpenIdAuthPlugin plugin = new OpenIdAuthPlugin(eventPublisher, userAuthService);
        URI uri = new ClassPathResource("config").getURI();
        ConfigPaths configPaths = new ConfigPaths(Collections.singletonList(Paths.get(uri)));
        AuthenticationProviderConfigurationLocator authenticationProviderConfigurationLocator =
                new AuthenticationProviderConfigurationLocator(configPaths, null);
        plugin.setAuthenticationProviderConfigurationLocator(authenticationProviderConfigurationLocator);

        subject = new OpenIdConnectFilter("/openid-login", plugin, eventPublisher, userAuthService) {
            @Override
            protected SiteConfigPreferences getSiteConfigPreferences() {
                return siteConfigPreferences;
            }
        };

        HttpServletRequest mockRequest = new MockHttpServletRequest();

        ((MockHttpServletRequest) mockRequest).setParameter("providerId", "test");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(mockRequest));

        Map<String, String[]> parameters = new HashMap<>();
        String csrfState = "CSRF-state";
        parameters.put("state", new String[]{csrfState});

        AccessTokenRequest accessTokenRequest = new DefaultAccessTokenRequest(parameters);
        accessTokenRequest.setPreservedState(csrfState);

        DefaultOAuth2ClientContext clientContext = new DefaultOAuth2ClientContext(accessTokenRequest);
        clientContext.setPreservedState(csrfState, csrfState);

        OAuth2RestTemplate restTemplate = plugin.createRestTemplate(clientContext);
        ReflectionTestUtils.setField(subject, "restTemplate", restTemplate);
    }

    @Test
    public void attemptAuthentication() throws Exception {
        stubFor(post(urlEqualTo("/auth")).willReturn(aResponse().withStatus(302)
                .withHeader("Location", "http://localhost:8081?code=code")));

        String idToken = JwtHelper.encode(readFile("id_token.json"),
                new MacSigner("secret")).getEncoded();

        Map<String, Object> body = new HashMap<>();
        body.put("access_token", "test-token");
        body.put("id_token", idToken);
        String json = objectMapper.writeValueAsString(body);

        stubFor(post(urlEqualTo("/token")).willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(json)));
        stubFor(get(urlEqualTo("/userinfo")).willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(readFile("user_info.json"))));

        HttpServletRequest request = new MockHttpServletRequest();
        HttpServletResponse response = new MockHttpServletResponse();

        request.getSession().setAttribute("providerId", "test");

        String providerId = "test";
        String username = "test_1234567890";
        UserI user = mock(UserI.class);
        when(user.isEnabled()).thenReturn(true);
        when(user.isVerified()).thenReturn(true);
        when(user.isAccountNonLocked()).thenReturn(true);
        when(this.userAuthService.getUserDetailsByNameAndAuth(username, XdatUserAuthService.OPENID, providerId)).thenReturn(user);

        when(siteConfigPreferences.getEmailVerification()).thenReturn(true);
        Authentication authentication = subject.attemptAuthentication(request, response);

        assertNotNull(authentication);
        assertTrue(authentication instanceof OpenIdAuthToken);
        OpenIdAuthToken token = (OpenIdAuthToken) authentication;
        assertEquals(token.getProviderId(), providerId);
    }

    private String readFile(String fileName) throws IOException {
        return IOUtils.toString(new ClassPathResource(fileName).getInputStream(), defaultCharset());
    }
}
