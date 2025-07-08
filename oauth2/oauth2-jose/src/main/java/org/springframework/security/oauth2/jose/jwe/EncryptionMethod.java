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

/**
 * The JWE Encryption Method (enc) values for JWE content encryption algorithms.
 * 
 * @author Joe Grandja
 * @since 5.6
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7518#section-5.1">JWE Encryption Method</a>
 */
public enum EncryptionMethod {

	/**
	 * A128CBC-HS256 - AES_128_CBC_HMAC_SHA_256
	 */
	A128CBC_HS256("A128CBC-HS256"),

	/**
	 * A192CBC-HS384 - AES_192_CBC_HMAC_SHA_384  
	 */
	A192CBC_HS384("A192CBC-HS384"),

	/**
	 * A256CBC-HS512 - AES_256_CBC_HMAC_SHA_512
	 */
	A256CBC_HS512("A256CBC-HS512"),

	/**
	 * A128GCM - AES GCM using 128-bit key
	 */
	A128GCM("A128GCM"),

	/**
	 * A192GCM - AES GCM using 192-bit key
	 */
	A192GCM("A192GCM"),

	/**
	 * A256GCM - AES GCM using 256-bit key
	 */
	A256GCM("A256GCM");

	private final String name;

	EncryptionMethod(String name) {
		this.name = name;
	}

	/**
	 * Returns the name of the encryption method.
	 * 
	 * @return the name of the encryption method
	 */
	public String getName() {
		return this.name;
	}

	/**
	 * Returns the encryption method with the specified name.
	 *
	 * @param name the name of the encryption method
	 * @return the encryption method
	 */
	public static EncryptionMethod from(String name) {
		for (EncryptionMethod method : values()) {
			if (method.getName().equals(name)) {
				return method;
			}
		}
		throw new IllegalArgumentException("Unknown encryption method: " + name);
	}
}