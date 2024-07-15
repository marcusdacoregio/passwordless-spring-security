package org.example.passwordless;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.passwordless.ott.OneTimeToken;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.passwordless.ott.OneTimeTokenAuthenticationRequestSuccessHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponentsBuilder;

public class MagicLinkOneTimeTokenSuccessHandler implements OneTimeTokenAuthenticationRequestSuccessHandler {

	private final MailSender mailSender;

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	public MagicLinkOneTimeTokenSuccessHandler(MailSender mailSender) {
		this.mailSender = mailSender;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, OneTimeToken oneTimeToken) throws ServletException, IOException {
		UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replacePath(request.getContextPath())
				.replaceQuery(null)
				.fragment(null)
				.path("/login/ott")
				.queryParam("token", oneTimeToken.getToken());
		String magicLink = builder.toUriString();
		this.mailSender.send("johndoe@example.com", "Your Spring Security One Time Token", "Use the following link to sign in into the application: " + magicLink);
		this.redirectStrategy.sendRedirect(request, response, "/ott/sent");
	}

}
