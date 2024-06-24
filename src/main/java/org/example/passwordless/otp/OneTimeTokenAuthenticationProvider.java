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

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

public class OneTimeTokenAuthenticationProvider implements AuthenticationProvider {

	private final OneTimeTokenUserDetailsService otpUserDetailsService;

	private final OneTimeTokenGenerator otpGenerator = new InMemoryOneTimeTokenGenerator();

	public OneTimeTokenAuthenticationProvider(OneTimeTokenUserDetailsService otpUserDetailsService) {
		this.otpUserDetailsService = otpUserDetailsService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OneTimeTokenAuthenticationToken otpAuthenticationToken = (OneTimeTokenAuthenticationToken) authentication;
		OneTimeToken otp = this.otpGenerator.use(otpAuthenticationToken.getUserIdentifier(), otpAuthenticationToken.getToken());
		if (otp == null) {
			return null;
		}
		UserDetails user = this.otpUserDetailsService.loadUserByOneTimePassword(otp);
		if (user == null) {
			return null;
		}
		return new OneTimeTokenAuthenticationToken(otpAuthenticationToken.getToken(),
				user.getUsername(), user, user.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OneTimeTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
