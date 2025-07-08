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

import org.springframework.security.oauth2.jose.JwaAlgorithm;

/**
 * The JWE Algorithm implementation for JWE encryption algorithms.
 * 
 * @author Joe Grandja
 * @since 5.6
 * @see JwaAlgorithm
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7518#section-4.1">JWE Algorithm</a>
 */
public enum JweAlgorithm implements JwaAlgorithm {

	/**
	 * RSA1_5 - RSA PKCS#1 v1.5 Encryption
	 */
	RSA1_5("RSA1_5"),

	/**
	 * RSA-OAEP - RSA Optimal Asymmetric Encryption Padding
	 */
	RSA_OAEP("RSA-OAEP"),

	/**
	 * RSA-OAEP-256 - RSA Optimal Asymmetric Encryption Padding using SHA-256
	 */
	RSA_OAEP_256("RSA-OAEP-256"),

	/**
	 * A128KW - AES Key Wrap using 128-bit key
	 */
	A128KW("A128KW"),

	/**
	 * A192KW - AES Key Wrap using 192-bit key
	 */
	A192KW("A192KW"),

	/**
	 * A256KW - AES Key Wrap using 256-bit key
	 */
	A256KW("A256KW"),

	/**
	 * dir - Direct use of a shared symmetric key
	 */
	DIR("dir"),

	/**
	 * ECDH-ES - Elliptic Curve Diffie-Hellman Ephemeral Static key agreement
	 */
	ECDH_ES("ECDH-ES"),

	/**
	 * ECDH-ES+A128KW - Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using AES Key Wrap with a 128-bit key
	 */
	ECDH_ES_A128KW("ECDH-ES+A128KW"),

	/**
	 * ECDH-ES+A192KW - Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using AES Key Wrap with a 192-bit key
	 */
	ECDH_ES_A192KW("ECDH-ES+A192KW"),

	/**
	 * ECDH-ES+A256KW - Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using AES Key Wrap with a 256-bit key
	 */
	ECDH_ES_A256KW("ECDH-ES+A256KW"),

	/**
	 * A128GCMKW - AES-GCM Key Wrap using 128-bit key
	 */
	A128GCMKW("A128GCMKW"),

	/**
	 * A192GCMKW - AES-GCM Key Wrap using 192-bit key
	 */
	A192GCMKW("A192GCMKW"),

	/**
	 * A256GCMKW - AES-GCM Key Wrap using 256-bit key
	 */
	A256GCMKW("A256GCMKW"),

	/**
	 * PBES2-HS256+A128KW - PBES2 with HMAC SHA-256 and AES Key Wrap with a 128-bit key
	 */
	PBES2_HS256_A128KW("PBES2-HS256+A128KW"),

	/**
	 * PBES2-HS384+A192KW - PBES2 with HMAC SHA-384 and AES Key Wrap with a 192-bit key
	 */
	PBES2_HS384_A192KW("PBES2-HS384+A192KW"),

	/**
	 * PBES2-HS512+A256KW - PBES2 with HMAC SHA-512 and AES Key Wrap with a 256-bit key
	 */
	PBES2_HS512_A256KW("PBES2-HS512+A256KW");

	private final String name;

	JweAlgorithm(String name) {
		this.name = name;
	}

	@Override
	public String getName() {
		return this.name;
	}

	/**
	 * Returns the JWE algorithm with the specified name.
	 *
	 * @param name the name of the JWE algorithm
	 * @return the JWE algorithm
	 */
	public static JweAlgorithm from(String name) {
		for (JweAlgorithm algorithm : values()) {
			if (algorithm.getName().equals(name)) {
				return algorithm;
			}
		}
		throw new IllegalArgumentException("Unknown JWE algorithm: " + name);
	}
}