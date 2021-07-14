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
package au.edu.qcif.xnat.auth.openid.tokens;

import org.nrg.xnat.security.tokens.AbstractXnatAuthenticationToken;

/**
 * Plugin's XNAT Auth Request token
 */
public class OpenIdAuthRequestToken extends AbstractXnatAuthenticationToken {
	public OpenIdAuthRequestToken(final String username, final String providerId) {
		super(providerId, username, null);
	}

	public String toString() {
		return getPrincipal() + ": " + getProviderId();
	}

}
