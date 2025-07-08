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

import java.util.Map;
import java.util.function.Consumer;

import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.util.Assert;

/**
 * The JOSE header for a JSON Web Encryption (JWE).
 * 
 * @author Joe Grandja
 * @since 5.6
 * @see JoseHeader
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7516#section-4">JWE Header</a>
 */
public final class JweHeader extends JoseHeader {

	private JweHeader(Map<String, Object> headers) {
		super(headers);
	}

	/**
	 * Returns the JWE algorithm.
	 * 
	 * @return the JWE algorithm
	 */
	@SuppressWarnings("unchecked")
	@Override
	public JweAlgorithm getAlgorithm() {
		return super.getAlgorithm();
	}

	/**
	 * Returns the JWE encryption method.
	 * 
	 * @return the JWE encryption method
	 */
	public EncryptionMethod getEncryptionMethod() {
		return getHeader("enc");
	}

	/**
	 * Returns a new {@link Builder} for creating a {@link JweHeader}.
	 * 
	 * @param jweAlgorithm the JWE algorithm
	 * @param encryptionMethod the JWE encryption method
	 * @return the {@link Builder}
	 */
	public static Builder with(JweAlgorithm jweAlgorithm, EncryptionMethod encryptionMethod) {
		return new Builder(jweAlgorithm, encryptionMethod);
	}

	/**
	 * Returns a new {@link Builder} for creating a {@link JweHeader} based on the provided headers.
	 * 
	 * @param headers the headers
	 * @return the {@link Builder}
	 */
	public static Builder from(JweHeader headers) {
		return new Builder(headers);
	}

	/**
	 * A builder for {@link JweHeader}.
	 */
	public static final class Builder extends AbstractBuilder<JweHeader, Builder> {

		private Builder(JweAlgorithm jweAlgorithm, EncryptionMethod encryptionMethod) {
			Assert.notNull(jweAlgorithm, "jweAlgorithm cannot be null");
			Assert.notNull(encryptionMethod, "encryptionMethod cannot be null");
			algorithm(jweAlgorithm);
			header("enc", encryptionMethod);
		}

		private Builder(JweHeader headers) {
			Assert.notNull(headers, "headers cannot be null");
			Consumer<Map<String, Object>> headersConsumer = (h) -> h.putAll(headers.getHeaders());
			headers(headersConsumer);
		}

		/**
		 * Sets the JWE algorithm.
		 * 
		 * @param jweAlgorithm the JWE algorithm
		 * @return the {@link Builder}
		 */
		public Builder algorithm(JweAlgorithm jweAlgorithm) {
			Assert.notNull(jweAlgorithm, "jweAlgorithm cannot be null");
			return algorithm(jweAlgorithm.getName());
		}

		/**
		 * Sets the JWE encryption method.
		 * 
		 * @param encryptionMethod the JWE encryption method
		 * @return the {@link Builder}
		 */
		public Builder encryptionMethod(EncryptionMethod encryptionMethod) {
			Assert.notNull(encryptionMethod, "encryptionMethod cannot be null");
			return header("enc", encryptionMethod);
		}

		/**
		 * Builds a new {@link JweHeader}.
		 * 
		 * @return the {@link JweHeader}
		 */
		@Override
		public JweHeader build() {
			return new JweHeader(getHeaders());
		}
	}
}