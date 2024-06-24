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

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

public class OneTimeTokenAuthenticationRequestFilter extends OncePerRequestFilter {

	private RequestMatcher requestMatcher = new AntPathRequestMatcher("/otp/authenticate", "POST");

	private OneTimeTokenAuthenticationRequestResolver authenticationRequestResolver = new OneTimeTokenAuthenticationRequestResolver();

	private OneTimeTokenGenerator otpGenerator = new InMemoryOneTimeTokenGenerator();

	private OneTimeTokenResponseProcessor responseProcessor = new ParamBasedOneTimeTokenResponseProcessor();

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}
		OneTimeTokenAuthenticationRequest authenticationRequest = this.authenticationRequestResolver
			.resolve(request);
		if (authenticationRequest == null) {
			filterChain.doFilter(request, response);
			return;
		}
		OneTimeToken otp = this.otpGenerator.generate(authenticationRequest);
		this.responseProcessor.process(request, response, filterChain, otp);
	}

	static class ParamBasedOneTimeTokenResponseProcessor implements OneTimeTokenResponseProcessor {

		private OneTimeTokenResponseProcessor magicLink = new MagicLinkOneTimeTokenResponseProcessor();

		private OneTimeTokenResponseProcessor redirect = new RedirectOneTimeTokenResponseProcessor();

		@Override
		public void process(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, OneTimeToken oneTimeToken) throws ServletException, IOException {
			if (request.getQueryString().contains("magiclink")) {
				this.magicLink.process(request, response, filterChain, oneTimeToken);
				return;
			}
			this.redirect.process(request, response, filterChain, oneTimeToken);
		}
	}

	static class RedirectOneTimeTokenResponseProcessor implements OneTimeTokenResponseProcessor {

		@Override
		public void process(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, OneTimeToken oneTimeToken) throws ServletException, IOException {
			response.sendRedirect("/otp/confirm?username=" + oneTimeToken.getUserIdentifier());
		}

	}

	static class MagicLinkOneTimeTokenResponseProcessor implements OneTimeTokenResponseProcessor {

		@Override
		public void process(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, OneTimeToken oneTimeToken) throws ServletException, IOException {
			UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
					.replacePath(request.getContextPath())
					.replaceQuery(null)
					.fragment(null)
					.path("/otp/confirm")
					.queryParam("username", oneTimeToken.getUserIdentifier())
					.queryParam("token", oneTimeToken.getToken());
			System.out.println(builder.build(true).toUriString());
			response.sendRedirect("/otp/sent");
		}

	}

}
