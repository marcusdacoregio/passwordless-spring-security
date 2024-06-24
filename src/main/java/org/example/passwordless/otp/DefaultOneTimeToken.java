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

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.springframework.util.Assert;

public class DefaultOneTimeToken implements OneTimeToken {

	private final String token;

	private final String userIdentifier;

	private Instant expireAt = Instant.now().plus(5, ChronoUnit.MINUTES);

	public DefaultOneTimeToken(String token, String userIdentifier) {
		Assert.hasText(token, "token cannot be empty");
		Assert.hasText(userIdentifier, "userIdentifier cannot be empty");
		this.token = token;
		this.userIdentifier = userIdentifier;
	}

	@Override
	public String getToken() {
		return this.token;
	}

	@Override
	public String getUserIdentifier() {
		return this.userIdentifier;
	}

	public Instant getExpireAt() {
		return this.expireAt;
	}

	public void setExpireAt(Instant expireAt) {
		this.expireAt = expireAt;
	}

}
