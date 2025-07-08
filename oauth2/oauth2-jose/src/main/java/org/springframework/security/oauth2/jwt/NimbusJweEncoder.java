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

import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.AESEncrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.jose.jwe.JweAlgorithm;
import org.springframework.security.oauth2.jose.jwe.JweHeader;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * An implementation of a {@link JwtEncoder} that encodes a JSON Web Token (JWT) using the
 * JSON Web Encryption (JWE) Compact Serialization format. The public/secret key used for
 * encryption is supplied by the {@code com.nimbusds.jose.jwk.source.JWKSource}
 * provided via the constructor.
 *
 * <p>
 * <b>NOTE:</b> This implementation uses the Nimbus JOSE + JWT SDK.
 *
 * @author Joe Grandja
 * @since 5.6
 * @see JwtEncoder
 * @see com.nimbusds.jose.jwk.source.JWKSource
 * @see com.nimbusds.jose.jwk.JWK
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7516">JSON Web Encryption
 * (JWE)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7516#section-3.1">JWE
 * Compact Serialization</a>
 * @see <a target="_blank" href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus
 * JOSE + JWT SDK</a>
 */
public final class NimbusJweEncoder implements JwtEncoder {

	private static final String ENCODING_ERROR_MESSAGE_TEMPLATE = "An error occurred while attempting to encode the Jwt: %s";

	private static final Converter<JweHeader, JWEHeader> JWE_HEADER_CONVERTER = new JweHeaderConverter();

	private static final Converter<JwtClaimsSet, JWTClaimsSet> JWT_CLAIMS_SET_CONVERTER = new JwtClaimsSetConverter();

	// Cache for JWE encrypters to avoid recreating them for the same key
	private static final Map<String, JWEEncrypter> jweEncrypterCache = new ConcurrentHashMap<>();

	private final JWKSource<SecurityContext> jwkSource;

	private final JwtEncoder jwsEncoder;

	/**
	 * Constructs a {@code NimbusJweEncoder} using the provided {@code JWKSource}.
	 *
	 * @param jwkSource the {@code JWKSource}
	 */
	public NimbusJweEncoder(JWKSource<SecurityContext> jwkSource) {
		Assert.notNull(jwkSource, "jwkSource cannot be null");
		this.jwkSource = jwkSource;
		this.jwsEncoder = new NimbusJwtEncoder(jwkSource);
	}

	@Override
	public Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {
		Assert.notNull(parameters, "parameters cannot be null");

		// TODO: Future API enhancement - retrieve JWE header from parameters
		// For now, use default RSA-OAEP-256 with A256GCM
		JweHeader jweHeader = JweHeader.with(JweAlgorithm.RSA_OAEP_256, 
				org.springframework.security.oauth2.jose.jwe.EncryptionMethod.A256GCM).build();

		JwsHeader jwsHeader = parameters.getJwsHeader();
		JwtClaimsSet claims = parameters.getClaims();

		JWK jwk = selectJwk(jweHeader);
		jweHeader = addKeyIdentifierHeadersIfNecessary(jweHeader, jwk);

		JWEHeader jweHeader2 = JWE_HEADER_CONVERTER.convert(jweHeader);
		JWTClaimsSet jwtClaimsSet = JWT_CLAIMS_SET_CONVERTER.convert(claims);

		String payload;
		if (jwsHeader != null) {
			// Sign then encrypt (nested JWT)
			Jwt jws = this.jwsEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));
			payload = jws.getTokenValue();

			// Add content type for nested JWT
			jweHeader = JweHeader.from(jweHeader)
					.contentType("JWT")
					.build();
			jweHeader2 = JWE_HEADER_CONVERTER.convert(jweHeader);
		} else {
			// Encrypt only
			payload = jwtClaimsSet.toString();
		}

		JWEObject jweObject = new JWEObject(jweHeader2, new Payload(payload));

		try {
			// Resolve and create the appropriate JWE encrypter based on the key type
			JWEEncrypter encrypter = createJweEncrypter(jwk, jweHeader2);
			jweObject.encrypt(encrypter);
		} catch (JOSEException ex) {
			throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
					"Failed to encrypt the JWT -> " + ex.getMessage()), ex);
		}

		String jwe = jweObject.serialize();

		return new Jwt(jwe, claims.getIssuedAt(), claims.getExpiresAt(), jweHeader.getHeaders(),
				claims.getClaims());
	}

	private JWK selectJwk(JweHeader headers) {
		List<JWK> jwks;
		try {
			JWKSelector jwkSelector = new JWKSelector(createJwkMatcher(headers));
			jwks = this.jwkSource.get(jwkSelector, null);
		} catch (Exception ex) {
			throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
					"Failed to select a JWK encryption key -> " + ex.getMessage()), ex);
		}

		if (jwks.size() > 1) {
			throw new JwtEncodingException(String.format(ENCODING_ERROR_MESSAGE_TEMPLATE,
					"Found multiple JWK encryption keys for algorithm '" + headers.getAlgorithm().getName() + "'"));
		}

		if (jwks.isEmpty()) {
			throw new JwtEncodingException(
					String.format(ENCODING_ERROR_MESSAGE_TEMPLATE, "Failed to select a JWK encryption key"));
		}

		return jwks.get(0);
	}

	private static JWKMatcher createJwkMatcher(JweHeader headers) {
		JWEAlgorithm jweAlgorithm = JWEAlgorithm.parse(headers.getAlgorithm().getName());

		return new JWKMatcher.Builder()
				.keyType(KeyType.forAlgorithm(jweAlgorithm))
				.keyID(headers.getKeyId())
				.keyUses(KeyUse.ENCRYPTION, null)
				.algorithms(jweAlgorithm, null)
				.x509CertSHA256Thumbprint(Base64URL.from(headers.getX509SHA256Thumbprint()))
				.build();
	}

	private static JweHeader addKeyIdentifierHeadersIfNecessary(JweHeader headers, JWK jwk) {
		// Check if headers have already been added
		if (StringUtils.hasText(headers.getKeyId()) && StringUtils.hasText(headers.getX509SHA256Thumbprint())) {
			return headers;
		}
		// Check if headers can be added from JWK
		if (!StringUtils.hasText(jwk.getKeyID()) && jwk.getX509CertSHA256Thumbprint() == null) {
			return headers;
		}

		JweHeader.Builder headersBuilder = JweHeader.from(headers);
		if (!StringUtils.hasText(headers.getKeyId()) && StringUtils.hasText(jwk.getKeyID())) {
			headersBuilder.keyId(jwk.getKeyID());
		}
		if (!StringUtils.hasText(headers.getX509SHA256Thumbprint()) && jwk.getX509CertSHA256Thumbprint() != null) {
			headersBuilder.x509SHA256Thumbprint(jwk.getX509CertSHA256Thumbprint().toString());
		}

		return headersBuilder.build();
	}

	/**
	 * Creates the appropriate JWE encrypter based on the key type.
	 * This method resolves the FIXME issue by properly handling different key types.
	 *
	 * @param jwk the JWK to create the encrypter for
	 * @param jweHeader the JWE header
	 * @return the JWE encrypter
	 * @throws JOSEException if an error occurs creating the encrypter
	 */
	private static JWEEncrypter createJweEncrypter(JWK jwk, JWEHeader jweHeader) throws JOSEException {
		String cacheKey = jwk.getKeyID() + ":" + jweHeader.getAlgorithm() + ":" + jweHeader.getEncryptionMethod();
		
		return jweEncrypterCache.computeIfAbsent(cacheKey, k -> {
			try {
				if (jwk instanceof RSAKey) {
					return new RSAEncrypter((RSAKey) jwk);
				} else if (jwk instanceof ECKey) {
					return new ECDHEncrypter((ECKey) jwk);
				} else if (jwk instanceof OctetSequenceKey) {
					OctetSequenceKey octKey = (OctetSequenceKey) jwk;
					SecretKey secretKey = octKey.toSecretKey();
					
					// Handle different algorithms for symmetric keys
					JWEAlgorithm algorithm = jweHeader.getAlgorithm();
					if (JWEAlgorithm.DIR.equals(algorithm)) {
						return new DirectEncrypter(secretKey);
					} else if (JWEAlgorithm.A128KW.equals(algorithm) || 
							   JWEAlgorithm.A192KW.equals(algorithm) || 
							   JWEAlgorithm.A256KW.equals(algorithm)) {
						return new AESEncrypter(secretKey);
					} else {
						throw new JOSEException("Unsupported JWE algorithm for symmetric key: " + algorithm);
					}
				} else {
					throw new JOSEException("Unsupported JWK type: " + jwk.getKeyType());
				}
			} catch (JOSEException | KeyLengthException ex) {
				throw new RuntimeException("Failed to create JWE encrypter", ex);
			}
		});
	}

	/**
	 * Converter to convert from {@link JweHeader} to {@link JWEHeader}.
	 */
	private static class JweHeaderConverter implements Converter<JweHeader, JWEHeader> {

		@Override
		public JWEHeader convert(JweHeader headers) {
			JWEAlgorithm jweAlgorithm = JWEAlgorithm.parse(headers.getAlgorithm().getName());
			EncryptionMethod encryptionMethod = EncryptionMethod.parse(headers.getEncryptionMethod().getName());
			JWEHeader.Builder builder = new JWEHeader.Builder(jweAlgorithm, encryptionMethod);

			URL jwkSetUri = headers.getJwkSetUrl();
			if (jwkSetUri != null) {
				try {
					builder.jwkURL(jwkSetUri.toURI());
				} catch (Exception ex) {
					throw new IllegalArgumentException(
							"Unable to convert '" + JoseHeaderNames.JKU + "' JOSE header to a URI", ex);
				}
			}

			Map<String, Object> jwk = headers.getJwk();
			if (!CollectionUtils.isEmpty(jwk)) {
				try {
					builder.jwk(JWK.parse(jwk));
				} catch (Exception ex) {
					throw new IllegalArgumentException("Unable to convert '" + JoseHeaderNames.JWK + "' JOSE header",
							ex);
				}
			}

			String keyId = headers.getKeyId();
			if (StringUtils.hasText(keyId)) {
				builder.keyID(keyId);
			}

			URL x509Uri = headers.getX509Url();
			if (x509Uri != null) {
				try {
					builder.x509CertURL(x509Uri.toURI());
				} catch (Exception ex) {
					throw new IllegalArgumentException(
							"Unable to convert '" + JoseHeaderNames.X5U + "' JOSE header to a URI", ex);
				}
			}

			List<String> x509CertificateChain = headers.getX509CertificateChain();
			if (!CollectionUtils.isEmpty(x509CertificateChain)) {
				builder.x509CertChain(x509CertificateChain.stream().map(Base64::new).collect(Collectors.toList()));
			}

			String x509SHA1Thumbprint = headers.getX509SHA1Thumbprint();
			if (StringUtils.hasText(x509SHA1Thumbprint)) {
				builder.x509CertThumbprint(new Base64URL(x509SHA1Thumbprint));
			}

			String x509SHA256Thumbprint = headers.getX509SHA256Thumbprint();
			if (StringUtils.hasText(x509SHA256Thumbprint)) {
				builder.x509CertSHA256Thumbprint(new Base64URL(x509SHA256Thumbprint));
			}

			String type = headers.getType();
			if (StringUtils.hasText(type)) {
				builder.type(new JOSEObjectType(type));
			}

			String contentType = headers.getContentType();
			if (StringUtils.hasText(contentType)) {
				builder.contentType(contentType);
			}

			Set<String> critical = headers.getCritical();
			if (!CollectionUtils.isEmpty(critical)) {
				builder.criticalParams(critical);
			}

			Map<String, Object> customHeaders = headers.getHeaders()
				.entrySet()
				.stream()
				.filter((header) -> !JWEHeader.getRegisteredParameterNames().contains(header.getKey()))
				.collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
			if (!CollectionUtils.isEmpty(customHeaders)) {
				builder.customParams(customHeaders);
			}

			return builder.build();
		}
	}

	/**
	 * Converter to convert from {@link JwtClaimsSet} to {@link JWTClaimsSet}.
	 */
	private static class JwtClaimsSetConverter implements Converter<JwtClaimsSet, JWTClaimsSet> {

		@Override
		public JWTClaimsSet convert(JwtClaimsSet claims) {
			JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

			// NOTE: The value of the 'iss' claim is a String or URL (StringOrURI).
			Object issuer = claims.getClaim(JwtClaimNames.ISS);
			if (issuer != null) {
				builder.issuer(issuer.toString());
			}

			String subject = claims.getSubject();
			if (StringUtils.hasText(subject)) {
				builder.subject(subject);
			}

			List<String> audience = claims.getAudience();
			if (!CollectionUtils.isEmpty(audience)) {
				builder.audience(audience);
			}

			Instant expiresAt = claims.getExpiresAt();
			if (expiresAt != null) {
				builder.expirationTime(Date.from(expiresAt));
			}

			Instant notBefore = claims.getNotBefore();
			if (notBefore != null) {
				builder.notBeforeTime(Date.from(notBefore));
			}

			Instant issuedAt = claims.getIssuedAt();
			if (issuedAt != null) {
				builder.issueTime(Date.from(issuedAt));
			}

			String jwtId = claims.getId();
			if (StringUtils.hasText(jwtId)) {
				builder.jwtID(jwtId);
			}

			Map<String, Object> customClaims = new HashMap<>();
			claims.getClaims().forEach((name, value) -> {
				if (!JWTClaimsSet.getRegisteredNames().contains(name)) {
					customClaims.put(name, value);
				}
			});
			if (!customClaims.isEmpty()) {
				customClaims.forEach(builder::claim);
			}

			return builder.build();
		}
	}
}