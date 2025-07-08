/*
 * Copyright 2002-2021 the original author or authors.
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

import java.util.ArrayList;
import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.jwe.EncryptionMethod;
import org.springframework.security.oauth2.jose.jwe.JweAlgorithm;
import org.springframework.security.oauth2.jwt.JweHeader;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link NimbusJweEncoder} JSON Web Encryption (JWE) support.
 *
 * @author Joe Grandja
 */
public class NimbusJweEncoderTests {

	// @formatter:off
	private static final JweHeader DEFAULT_JWE_HEADER =
			JweHeader.with(JweAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).build();
	// @formatter:on

	private List<JWK> jwkList;

	private JWKSource<SecurityContext> jwkSource;

	private NimbusJweEncoder jweEncoder;

	@BeforeEach
	public void setUp() {
		this.jwkList = new ArrayList<>();
		this.jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(new JWKSet(this.jwkList));
		this.jweEncoder = new NimbusJweEncoder(this.jwkSource);
	}

	@Test
	public void encodeWhenJwtClaimsSetThenEncodes() {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		this.jwkList.add(rsaJwk);

		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt encodedJwe = this.jweEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet));

		assertThat(encodedJwe.getHeaders()).containsEntry(JoseHeaderNames.ALG, DEFAULT_JWE_HEADER.getAlgorithm().getName());
		assertThat(encodedJwe.getHeaders()).containsEntry("enc", DEFAULT_JWE_HEADER.getEncryptionMethod().getName());
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.JKU)).isNull();
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.JWK)).isNull();
		assertThat(encodedJwe.getHeaders()).containsEntry(JoseHeaderNames.KID, rsaJwk.getKeyID());
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.X5U)).isNull();
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.X5C)).isNull();
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.X5T)).isNull();
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.X5T_S256)).isNull();
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.TYP)).isNull();
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.CTY)).isNull();
		assertThat(encodedJwe.getHeaders().get(JoseHeaderNames.CRIT)).isNull();

		assertThat(encodedJwe.getIssuer()).isEqualTo(jwtClaimsSet.getIssuer());
		assertThat(encodedJwe.getSubject()).isEqualTo(jwtClaimsSet.getSubject());
		assertThat(encodedJwe.getAudience()).isEqualTo(jwtClaimsSet.getAudience());
		assertThat(encodedJwe.getExpiresAt()).isEqualTo(jwtClaimsSet.getExpiresAt());
		assertThat(encodedJwe.getNotBefore()).isEqualTo(jwtClaimsSet.getNotBefore());
		assertThat(encodedJwe.getIssuedAt()).isEqualTo(jwtClaimsSet.getIssuedAt());
		assertThat(encodedJwe.getId()).isEqualTo(jwtClaimsSet.getId());
		assertThat(encodedJwe.<String>getClaim("custom-claim-name")).isEqualTo("custom-claim-value");

		assertThat(encodedJwe.getTokenValue()).isNotNull();
	}

	@Test
	public void encodeWhenNestedJwsThenEncodes() {
		// See Nimbus example -> Nested signed and encrypted JWT
		// https://connect2id.com/products/nimbus-jose-jwt/examples/signed-and-encrypted-jwt

		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		this.jwkList.add(rsaJwk);

		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
		JwtClaimsSet jwtClaimsSet = TestJwtClaimsSets.jwtClaimsSet().build();

		Jwt encodedJweNestedJws = this.jweEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet));

		assertThat(encodedJweNestedJws.getHeaders()).containsEntry(JoseHeaderNames.ALG,
				DEFAULT_JWE_HEADER.getAlgorithm().getName());
		assertThat(encodedJweNestedJws.getHeaders()).containsEntry("enc", DEFAULT_JWE_HEADER.getEncryptionMethod().getName());
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.JKU)).isNull();
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.JWK)).isNull();
		assertThat(encodedJweNestedJws.getHeaders()).containsEntry(JoseHeaderNames.KID, rsaJwk.getKeyID());
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.X5U)).isNull();
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.X5C)).isNull();
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.X5T)).isNull();
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.X5T_S256)).isNull();
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.TYP)).isNull();
		assertThat(encodedJweNestedJws.getHeaders()).containsEntry(JoseHeaderNames.CTY, "JWT");
		assertThat(encodedJweNestedJws.getHeaders().get(JoseHeaderNames.CRIT)).isNull();

		assertThat(encodedJweNestedJws.getIssuer()).isEqualTo(jwtClaimsSet.getIssuer());
		assertThat(encodedJweNestedJws.getSubject()).isEqualTo(jwtClaimsSet.getSubject());
		assertThat(encodedJweNestedJws.getAudience()).isEqualTo(jwtClaimsSet.getAudience());
		assertThat(encodedJweNestedJws.getExpiresAt()).isEqualTo(jwtClaimsSet.getExpiresAt());
		assertThat(encodedJweNestedJws.getNotBefore()).isEqualTo(jwtClaimsSet.getNotBefore());
		assertThat(encodedJweNestedJws.getIssuedAt()).isEqualTo(jwtClaimsSet.getIssuedAt());
		assertThat(encodedJweNestedJws.getId()).isEqualTo(jwtClaimsSet.getId());
		assertThat(encodedJweNestedJws.<String>getClaim("custom-claim-name")).isEqualTo("custom-claim-value");

		assertThat(encodedJweNestedJws.getTokenValue()).isNotNull();
	}

}
