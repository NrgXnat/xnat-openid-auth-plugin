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

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.axis.utils.StringUtils;
import org.nrg.xdat.security.XDATUser;
import org.nrg.xnat.security.XnatAuthenticationFilter;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.*;

/**
 * OIDC user details
 *
 * @author <a href='https://github.com/shilob'>Shilo Banihit</a>
 */
public class OpenIdConnectUserDetails extends XDATUser {

    private static final long serialVersionUID = 1L;
    private static final String DEFAULT_USERNAME_PATTERN = "[providerId]_[sub]";

    private OAuth2AccessToken token;
    private String email;
    private Map<String, String> openIdUserInfo;
    private String name;
    private String picture;
    private String firstName;
    private String lastName;
    private String pw;
    private String username;
    private String providerId;
    private OpenIdAuthPlugin plugin;

    public OpenIdConnectUserDetails(
            String providerId,
            Map<String, String> userInfo,
            OAuth2AccessToken token,
            OpenIdAuthPlugin plugin) {
        this.openIdUserInfo = userInfo;
        this.providerId = providerId;
        this.setUsername(resolvePattern(plugin.getProperty(providerId, USERNAME_PATTERN)));
        this.token = token;
        this.plugin = plugin;

        this.email = getUserInfo(userInfo, EMAIL, "");
        this.setFirstname(getUserInfo(userInfo, GIVEN_NAME, ""));
        this.setLastname(getUserInfo(userInfo, FAMILY_NAME, ""));
        this.name = userInfo.get("name");
        this.picture = userInfo.get("picture");
    }

    private String getUserInfo(Map<String, String> userInfo, String propName, String defaultVal) {
        String propVal = userInfo.get(plugin.getProperty(providerId, propName));
        return propVal != null ? propVal : defaultVal;
    }

    private String resolvePattern(String usernamePattern) {
        if (StringUtils.isEmpty(usernamePattern)) {
            usernamePattern = DEFAULT_USERNAME_PATTERN;
        }

        Pattern pattern = Pattern.compile("\\[([a-zA-Z0-9]+)\\]");
        Matcher m = pattern.matcher(usernamePattern);

        HashMap<String, String> pairs = new HashMap<>();

        int idx = 0;
        while (m.find(idx)) {
            String raw = m.group(0);
            String variableName = m.group(1);

            pairs.put(raw, variableName);
            idx = m.end();
        }

        String converted = usernamePattern;
        for (String key : pairs.keySet()) {
            String fieldName = pairs.get(key);
            String value = getFieldValue(fieldName);
            converted = converted.replace(key, value);
        }
        return converted;
    }

    public String getFieldValue(String fieldName) {
        String value = null;
        try {
            Field field = this.getClass().getDeclaredField(fieldName);
            value = (String) field.get(this);
        } catch (Exception e) {
            if (openIdUserInfo != null) {
                value = openIdUserInfo.get(fieldName);
            }
        }
        return value;
    }

    public String getOpenIdUserInfo(String propName) {
        return getOpenIdUserInfo(propName, null);
    }

    public String getOpenIdUserInfo(String propName, String defaultVal) {
        if (openIdUserInfo == null) {
            return defaultVal;
        }

        String propVal = openIdUserInfo.get(plugin.getProperty(providerId, propName));
        return propVal != null ? propVal : defaultVal;
    }

    public OAuth2AccessToken getToken() {
        return token;
    }
    
    public void setToken(OAuth2AccessToken token) {
        this.token = token;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public String getFirstname() {
        return firstName;
    }

    public String getLastname() {
        return lastName;
    }

    public String getEmail() {
        return this.email;
    }

    public void setEmail(String e) {
        this.email = e;
    }

    public void setFirstname(String firstname) {
        this.firstName = firstname;
    }

    public void setLastname(String lastname) {
        this.lastName = lastname;
    }

}
