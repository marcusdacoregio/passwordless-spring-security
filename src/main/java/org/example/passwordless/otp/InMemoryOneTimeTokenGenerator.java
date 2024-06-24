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

import java.time.Clock;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

// TODO generator might not be a good name since it does not only generate, maybe OneTimeTokenStorage?
public class InMemoryOneTimeTokenGenerator implements OneTimeTokenGenerator {

	private static final Map<String, OneTimeToken> tokensByUser = new ConcurrentHashMap<>();

	public static String lastToken;

	private final Clock clock = Clock.systemUTC();

	@Override
	public OneTimeToken generate(OneTimeTokenAuthenticationRequest request) {
		String token = String.format("%06d", new Random().nextInt(1_000_000));
		System.out.println("Generated token: " + token);
		lastToken = token;
		DefaultOneTimeToken ott = new DefaultOneTimeToken(token, request.getUserIdentifier());
		tokensByUser.put(request.getUserIdentifier(), ott);
		return ott;
	}

	@Override
	public OneTimeToken use(String userIdentifier, String token) {
		OneTimeToken oneTimeToken = tokensByUser.get(userIdentifier);
		if (oneTimeToken == null) {
			return null;
		}
		if (isExpired(oneTimeToken)) {
			tokensByUser.remove(userIdentifier);
			return null;
		}
		if (!oneTimeToken.getToken().equals(token)) {
			return null;
		}
		tokensByUser.remove(userIdentifier);
		return oneTimeToken;
	}

	private boolean isExpired(OneTimeToken ott) {
		return this.clock.instant().isAfter(ott.getExpireAt());
	}

}
