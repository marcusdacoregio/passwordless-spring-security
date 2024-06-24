/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.example.passwordless.otp;

import java.util.Collection;
import java.util.Collections;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class OneTimeTokenAuthenticationToken extends AbstractAuthenticationToken {

	private final String token;

	private final String userIdentifier;

	private final Object principal;

	public OneTimeTokenAuthenticationToken(String token, String userIdentifier) {
		super(Collections.emptyList());
		this.token = token;
		this.userIdentifier = userIdentifier;
		this.principal = userIdentifier;
	}

	OneTimeTokenAuthenticationToken(String token, String userIdentifier, Object principal,
									Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.token = token;
		this.userIdentifier = userIdentifier;
		this.principal = principal;
		setAuthenticated(true);
	}

	public String getToken() {
		return this.token;
	}

	public String getUserIdentifier() {
		return this.userIdentifier;
	}

	@Override
	public Object getCredentials() {
		return this.token;
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

}
