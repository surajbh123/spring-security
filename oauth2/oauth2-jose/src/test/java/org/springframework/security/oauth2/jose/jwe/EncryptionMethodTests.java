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
 * Tests for {@link EncryptionMethod}.
 *
 * @author Joe Grandja
 */
public class EncryptionMethodTests {

	@Test
	public void fromWhenValidEncryptionMethodThenReturnEncryptionMethod() {
		assertThat(EncryptionMethod.from("A128GCM")).isEqualTo(EncryptionMethod.A128GCM);
		assertThat(EncryptionMethod.from("A192GCM")).isEqualTo(EncryptionMethod.A192GCM);
		assertThat(EncryptionMethod.from("A256GCM")).isEqualTo(EncryptionMethod.A256GCM);
		assertThat(EncryptionMethod.from("A128CBC-HS256")).isEqualTo(EncryptionMethod.A128CBC_HS256);
		assertThat(EncryptionMethod.from("A192CBC-HS384")).isEqualTo(EncryptionMethod.A192CBC_HS384);
		assertThat(EncryptionMethod.from("A256CBC-HS512")).isEqualTo(EncryptionMethod.A256CBC_HS512);
	}

	@Test
	public void fromWhenInvalidEncryptionMethodThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> EncryptionMethod.from("invalid"))
				.withMessage("Unknown encryption method: invalid");
	}

	@Test
	public void getNameWhenCalledThenReturnName() {
		assertThat(EncryptionMethod.A128GCM.getName()).isEqualTo("A128GCM");
		assertThat(EncryptionMethod.A256GCM.getName()).isEqualTo("A256GCM");
		assertThat(EncryptionMethod.A128CBC_HS256.getName()).isEqualTo("A128CBC-HS256");
		assertThat(EncryptionMethod.A256CBC_HS512.getName()).isEqualTo("A256CBC-HS512");
	}
}