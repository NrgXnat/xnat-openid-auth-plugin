package au.edu.qcif.xnat.auth.openid.provider;

import au.edu.qcif.xnat.auth.openid.tokens.OpenIdAuthRequestToken;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xnat.security.provider.ProviderAttributes;
import org.nrg.xnat.security.provider.XnatAuthenticationProvider;
import org.nrg.xnat.security.tokens.XnatAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

@Slf4j
public class XnatOpenIdAuthenticationProvider implements XnatAuthenticationProvider {
    public XnatOpenIdAuthenticationProvider(
            final ProviderAttributes attributes
    ) {
        setProviderId(attributes.getProviderId());
        setName(attributes.getName());
    }

    public XnatOpenIdAuthenticationProvider(
            final String providerId,
            final ProviderAttributes attributes
    ) {
        setProviderId(providerId);
        setName(attributes.getName());
    }

    @Override
    public String getProviderId() {
        return _providerId;
    }

    public void setProviderId(final String providerId) {
        _providerId = providerId;
    }

    @Override
    public String getAuthMethod() {
        return XdatUserAuthService.OPENID;
    }

    @Override
    public String getName() {
        return _displayName;
    }

    public void setName(final String newName) {
        _displayName = newName;
    }

    @Override
    public boolean isVisible() {
        return _visible;
    }

    @Override
    public void setVisible(final boolean visible) {
    }

    @Override
    public boolean isAutoEnabled() {
        return _autoEnabled;
    }

    @Override
    public void setAutoEnabled(final boolean autoEnabled) {
        _autoEnabled = autoEnabled;
    }

    @Override
    public boolean isAutoVerified() {
        return _autoVerified;
    }

    @Override
    public void setAutoVerified(final boolean autoVerified) {
        _autoVerified = autoVerified;
    }

    @Deprecated
    @Override
    public int getOrder() {
        log.info("The order property is deprecated and will be removed in a future version of XNAT.");
        return 0;
    }

    @Deprecated
    @Override
    public void setOrder(int order) {
        log.info("The order property is deprecated and will be removed in a future version of XNAT.");
    }

    @Override
    public XnatAuthenticationToken createToken(String username, String password) {
        return new OpenIdAuthRequestToken(username, getProviderId());
    }

    @Override
    public boolean supports(Authentication authentication) {
        return supports(authentication.getClass()) &&
                authentication instanceof OpenIdAuthRequestToken &&
                StringUtils.equals(getProviderId(), ((OpenIdAuthRequestToken) authentication).getProviderId());
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.info("This is the dummy provider");
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return false;
    }

    private String _displayName = "";
    private String _providerId = "";
    //This plugin should be invisible so that the user only can login via OAuth process.
    boolean _visible = false;
    private boolean _autoEnabled;
    private boolean _autoVerified;
}
