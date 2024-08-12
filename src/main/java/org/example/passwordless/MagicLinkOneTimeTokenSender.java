package org.example.passwordless;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenSender;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.UriComponentsBuilder;

@Component
public class MagicLinkOneTimeTokenSender implements OneTimeTokenSender {

	private final MailSender mailSender;

	public MagicLinkOneTimeTokenSender(MailSender mailSender) {
		this.mailSender = mailSender;
	}

	@Override
	public void send(OneTimeToken oneTimeToken) {
		ServletRequestAttributes requestAttributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		HttpServletRequest request = requestAttributes.getRequest();
		UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replacePath(request.getContextPath())
				.replaceQuery(null)
				.fragment(null)
				.path("/login/ott")
				.queryParam("token", oneTimeToken.getToken());
		String magicLink = builder.toUriString();
		this.mailSender.send("johndoe@example.com", "Your Spring Security One Time Token", "Use the following link to sign in into the application: " + magicLink);
	}

}
