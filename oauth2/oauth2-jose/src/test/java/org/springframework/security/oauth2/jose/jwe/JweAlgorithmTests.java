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

package org.springframework.security.oauth2.jose.jwe;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link JweAlgorithm}.
 *
 * @author Joe Grandja
 */
public class JweAlgorithmTests {

	@Test
	public void fromWhenValidAlgorithmThenReturnAlgorithm() {
		assertThat(JweAlgorithm.from("RSA-OAEP-256")).isEqualTo(JweAlgorithm.RSA_OAEP_256);
		assertThat(JweAlgorithm.from("RSA-OAEP")).isEqualTo(JweAlgorithm.RSA_OAEP);
		assertThat(JweAlgorithm.from("A256KW")).isEqualTo(JweAlgorithm.A256KW);
		assertThat(JweAlgorithm.from("dir")).isEqualTo(JweAlgorithm.DIR);
		assertThat(JweAlgorithm.from("ECDH-ES")).isEqualTo(JweAlgorithm.ECDH_ES);
	}

	@Test
	public void fromWhenInvalidAlgorithmThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> JweAlgorithm.from("invalid"))
				.withMessage("Unknown JWE algorithm: invalid");
	}

	@Test
	public void getNameWhenCalledThenReturnName() {
		assertThat(JweAlgorithm.RSA_OAEP_256.getName()).isEqualTo("RSA-OAEP-256");
		assertThat(JweAlgorithm.A256KW.getName()).isEqualTo("A256KW");
		assertThat(JweAlgorithm.DIR.getName()).isEqualTo("dir");
		assertThat(JweAlgorithm.ECDH_ES.getName()).isEqualTo("ECDH-ES");
	}
}