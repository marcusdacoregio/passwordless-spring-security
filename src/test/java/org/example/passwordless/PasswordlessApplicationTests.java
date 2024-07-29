package org.example.passwordless;

import jakarta.mail.internet.MimeMessage;
import com.icegreen.greenmail.junit5.GreenMailExtension;
import com.icegreen.greenmail.util.GreenMailUtil;
import com.icegreen.greenmail.util.ServerSetupTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class PasswordlessApplicationTests {

	@RegisterExtension
	static GreenMailExtension greenMail = new GreenMailExtension(ServerSetupTest.SMTP);

	@Autowired
	MockMvc mockMvc;

	@Test
	void ottAuthenticationRequestWhenUserExistsThenSendEmailAndAuthenticate() throws Exception {
		this.mockMvc.perform(post("/ott/authenticate").param("username", "user").with(csrf()))
				.andExpectAll(
						status().isFound(),
						redirectedUrl("/ott/sent")
				);

		greenMail.waitForIncomingEmail(1);
		MimeMessage receivedMessage = greenMail.getReceivedMessages()[0];
		String content = GreenMailUtil.getBody(receivedMessage);
		String url = content.split(": ")[1];
		UriComponents uriComponents = UriComponentsBuilder.fromUriString(url).build();
		String token = uriComponents.getQueryParams().get("token").get(0);

		assertThat(token).isNotEmpty();

		this.mockMvc.perform(post("/login/ott").param("token", token).with(csrf()))
				.andExpectAll(
						status().isFound(),
						redirectedUrl("/"),
						authenticated()
				);
	}

}
