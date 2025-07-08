/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.oauth2.jwt;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jwe.EncryptionMethod;
import org.springframework.security.oauth2.jose.jwe.JweAlgorithm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link JweHeader}.
 *
 * @author Joe Grandja
 */
public class JweHeaderTests {

	@Test
	public void withWhenJweAlgorithmNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> JweHeader.with(null, EncryptionMethod.A256GCM))
				.withMessage("jweAlgorithm cannot be null");
	}

	@Test
	public void withWhenEncryptionMethodNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> JweHeader.with(JweAlgorithm.RSA_OAEP_256, null))
				.withMessage("encryptionMethod cannot be null");
	}

	@Test
	public void buildWhenAllHeadersProvidedThenAllHeadersAreSet() {
		JweHeader jweHeader = JweHeader.with(JweAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
				.keyId("key-id")
				.type("JWT")
				.contentType("application/json")
				.build();

		assertThat(jweHeader.getAlgorithm()).isEqualTo(JweAlgorithm.RSA_OAEP_256);
		assertThat(jweHeader.getEncryptionMethod()).isEqualTo(EncryptionMethod.A256GCM);
		assertThat(jweHeader.getKeyId()).isEqualTo("key-id");
		assertThat(jweHeader.getType()).isEqualTo("JWT");
		assertThat(jweHeader.getContentType()).isEqualTo("application/json");
	}

	@Test
	public void fromWhenJweHeaderNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> JweHeader.from(null))
				.withMessage("headers cannot be null");
	}

	@Test
	public void fromWhenJweHeaderProvidedThenCopyAllHeaders() {
		JweHeader originalHeader = JweHeader.with(JweAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
				.keyId("key-id")
				.type("JWT")
				.build();

		JweHeader copiedHeader = JweHeader.from(originalHeader)
				.contentType("application/json")
				.build();

		assertThat(copiedHeader.getAlgorithm()).isEqualTo(JweAlgorithm.RSA_OAEP_256);
		assertThat(copiedHeader.getEncryptionMethod()).isEqualTo(EncryptionMethod.A256GCM);
		assertThat(copiedHeader.getKeyId()).isEqualTo("key-id");
		assertThat(copiedHeader.getType()).isEqualTo("JWT");
		assertThat(copiedHeader.getContentType()).isEqualTo("application/json");
	}

	@Test
	public void algorithmWhenJweAlgorithmNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> JweHeader.with(JweAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
						.algorithm((JweAlgorithm) null))
				.withMessage("jweAlgorithm cannot be null");
	}

	@Test
	public void encryptionMethodWhenEncryptionMethodNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> JweHeader.with(JweAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
						.encryptionMethod(null))
				.withMessage("encryptionMethod cannot be null");
	}

	@Test
	public void algorithmWhenJweAlgorithmProvidedThenSet() {
		JweHeader jweHeader = JweHeader.with(JweAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
				.algorithm(JweAlgorithm.A256KW)
				.build();

		assertThat(jweHeader.getAlgorithm()).isEqualTo(JweAlgorithm.A256KW);
	}

	@Test
	public void encryptionMethodWhenEncryptionMethodProvidedThenSet() {
		JweHeader jweHeader = JweHeader.with(JweAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
				.encryptionMethod(EncryptionMethod.A128GCM)
				.build();

		assertThat(jweHeader.getEncryptionMethod()).isEqualTo(EncryptionMethod.A128GCM);
	}
}