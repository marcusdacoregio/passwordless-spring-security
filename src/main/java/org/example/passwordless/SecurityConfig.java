/*
 * Copyright 2024 the original author or authors.
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

package org.example.passwordless;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.ott.GeneratedOneTimeTokenHandler;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http, MagicLinkGeneratedOneTimeTokenHandler magicLinkGeneratedOneTimeTokenHandler) throws Exception {
		// @formatter:off
		http
				.authorizeHttpRequests((authz) -> authz
						.requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
						.requestMatchers("/ott/sent").permitAll()
						.anyRequest().authenticated())
				.formLogin(Customizer.withDefaults())
				.oneTimeTokenLogin((ott) -> ott
						.generatedOneTimeTokenHandler(magicLinkGeneratedOneTimeTokenHandler)
				);
//				.oneTimeTokenLogin(Customizer.withDefaults());
		// @formatter:on
		return http.build();
	}

	@Bean
	InMemoryUserDetailsManager userDetailsService() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(user);
	}

	public final class MyTest implements GeneratedOneTimeTokenHandler {

		static final String SPRING_SECURITY_ONE_TIME_TOKEN = "SPRING_SECURITY_ONE_TIME_TOKEN";

		@Override
		public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken oneTimeToken)
				throws IOException, ServletException {
			HttpSession session = request.getSession(false);
			session.setAttribute(SPRING_SECURITY_ONE_TIME_TOKEN, oneTimeToken);
			new DefaultRedirectStrategy().sendRedirect(request, response, "/ott/sent");
		}

	}

}
