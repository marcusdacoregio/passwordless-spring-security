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

import java.util.ArrayList;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import org.example.passwordless.otp.OneTimeTokenAuthenticationConverter;
import org.example.passwordless.otp.OneTimeTokenAuthenticationProvider;
import org.example.passwordless.otp.OneTimeTokenAuthenticationRequestFilter;
import org.example.passwordless.otp.OneTimeTokenUserDetailsService;
import org.example.passwordless.otp.PasswordlessAuthenticationFilter;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.Assert;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
				.authorizeHttpRequests((authz) -> authz
						.requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
						.requestMatchers("/otp/authenticate", "/otp/confirm", "/otp/sent").permitAll()
						.anyRequest().authenticated())
				.formLogin((login) -> login
						.loginPage("/login")
						.permitAll()
				)
				.with(PasswordlessLogin.passwordlessLogin(), (passwordless) -> passwordless
						.oneTimeToken()
				);
		// @formatter:on
		return http.build();
	}

	@Bean
	UserDetailsService userDetailsService() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.roles("USER")
				.build();
		return new InMemoryUserDetailsManager(user);
	}

	public static class PasswordlessLogin extends AbstractHttpConfigurer<PasswordlessLogin, HttpSecurity> {

		private boolean configureOtp;

		@Override
		public void init(HttpSecurity http) throws Exception {

		}

		@Override
		public void configure(HttpSecurity http) throws Exception {
			ApplicationContext context = http.getSharedObject(ApplicationContext.class);

			http.addFilterAfter(passwordlessAuthenticationFilter(context.getBean(UserDetailsService.class)), UsernamePasswordAuthenticationFilter.class);
			if (this.configureOtp) {
//				http.addFilterBefore(new DefaultOtpPageGeneratingFilter(), DefaultLoginPageGeneratingFilter.class);
//				http.addFilterBefore(new DefaultOtpConfirmationPageGeneratingFilter(), DefaultLoginPageGeneratingFilter.class);
				http.addFilterBefore(new OneTimeTokenAuthenticationRequestFilter(),
						UsernamePasswordAuthenticationFilter.class);
			}
		}

		private PasswordlessAuthenticationFilter passwordlessAuthenticationFilter(UserDetailsService userDetailsService) {
			OneTimeTokenUserDetailsService otpUserDetailsService = otp -> userDetailsService.loadUserByUsername(otp.getUserIdentifier());
			var manager = new ProviderManager(new OneTimeTokenAuthenticationProvider(otpUserDetailsService));
			var converter = new DelegatingAuthenticationConverter(new OneTimeTokenAuthenticationConverter());
			return new PasswordlessAuthenticationFilter(manager, converter);
		}

		public PasswordlessLogin oneTimeToken() {
			this.configureOtp = true;
			return this;
		}

		public static PasswordlessLogin passwordlessLogin() {
			return new PasswordlessLogin();
		}
	}

	public static final class DelegatingAuthenticationConverter implements AuthenticationConverter {

		private final List<AuthenticationConverter> delegates;

		public DelegatingAuthenticationConverter(List<AuthenticationConverter> delegates) {
			Assert.notEmpty(delegates, "delegates cannot be null");
			this.delegates = new ArrayList<>(delegates);
		}

		public DelegatingAuthenticationConverter(AuthenticationConverter... delegates) {
			Assert.notEmpty(delegates, "delegates cannot be null");
			this.delegates = List.of(delegates);
		}

		@Override
		public Authentication convert(HttpServletRequest request) {
			for (AuthenticationConverter delegate : this.delegates) {
				Authentication authentication = delegate.convert(request);
				if (authentication != null) {
					return authentication;
				}
			}
			return null;
		}

	}

}
