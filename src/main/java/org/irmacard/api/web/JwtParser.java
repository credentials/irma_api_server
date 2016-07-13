package org.irmacard.api.web;

import com.google.gson.JsonParseException;
import com.google.gson.JsonSyntaxException;
import io.jsonwebtoken.*;
import org.irmacard.api.common.exceptions.ApiError;
import org.irmacard.api.common.exceptions.ApiException;
import org.irmacard.api.common.util.GsonUtil;

import java.security.Key;
import java.util.Calendar;
import java.util.Map;

/**
 * A JWT parser for incoming issuer or service provider requests.
 */
public class JwtParser <T> {
	private SigningKeyResolver keyResolver;
	private long maxAge;
	private boolean allowUnsigned;
	private String subject;
	private String field;
	private Class<T> clazz;

	private Claims claims;
	private T payload;

	/**
	 * Construct a new parser.
	 * @param allowUnsigned If unsigned JWT's should be allowed
	 * @param subject The expected subject of the JWT
	 * @param field The fieldname in which the request will be present
	 * @param keyPath Path in which to find the client's public key
	 * @param clazz Class of the request that will be present in the JWT's payload
	 */
	public JwtParser(boolean allowUnsigned, String subject, String field, final String keyPath, Class<T> clazz) {
		this.maxAge = ApiConfiguration.getInstance().getMaxJwtAge();
		this.allowUnsigned = allowUnsigned;
		this.subject = subject;
		this.field = field;
		this.clazz = clazz;

		keyResolver = new SigningKeyResolverAdapter() {
			@Override public Key resolveSigningKey(JwsHeader header, Claims claims) {
				return ApiConfiguration.getInstance().getClientPublicKey(keyPath, claims.getIssuer());
			}
		};
	}

	/**
	 * Parse the given JWT.
	 */
	public JwtParser<T> parseJwt(String jwt) {
		claims = getClaims(jwt);
		payload = parseClaims(claims);

		return this;
	}

	private Claims getSignedClaims(String jwt) {
		return Jwts.parser()
				.requireSubject(subject)
				.setSigningKeyResolver(keyResolver)
				.parseClaimsJws(jwt)
				.getBody();
	}

	private Claims getUnsignedClaims(String jwt) {
		return Jwts.parser()
				.requireSubject(subject)
				.parseClaimsJwt(jwt)
				.getBody();
	}

	/**
	 * Parse the specified String as a JWT, checking its age, and its signature if necessary.
	 * @param jwt The JWT
	 * @return The claims contained in the JWT
	 * @throws ApiException If there was no signature but there needed to be; if the signature did not
	 *                      verify; if the JWT was too old; or if the specified string could not be
	 *                      parsed as a JWT
	 */
	public Claims getClaims(String jwt) throws ApiException {
		Claims claims;

		try {
			if (!allowUnsigned) { // Has to be signed, only try as signed JWT
				System.out.println("Trying signed JWT");
				claims = getSignedClaims(jwt);
			} else { // First try to parse it as an unsigned JWT; if that fails, try it as a signed JWT
				try {
					System.out.println("Trying unsigned JWT");
					claims = getUnsignedClaims(jwt);
				} catch (UnsupportedJwtException e) {
					claims = getSignedClaims(jwt);
				}
			}
		} catch (UnsupportedJwtException|MalformedJwtException|SignatureException
				|ExpiredJwtException|IllegalArgumentException e) {
			throw new ApiException(ApiError.JWT_INVALID);
		}

		long now = Calendar.getInstance().getTimeInMillis();
		long issued_at = claims.getIssuedAt().getTime();
		if (now - issued_at > maxAge)
			throw new ApiException(ApiError.JWT_TOO_OLD, "Max age: " + maxAge + ", was " + (now - issued_at));

		return claims;
	}

	/**
	 * Extract the request from the specified claims.
	 * @throws ApiException if the request could not be deserialized as an instance of T
	 */
	public T parseClaims(Claims claims) throws ApiException {
		// Dirty Hack (tm): we can get a Map from Jwts, but we need an instance of T.
		// But if the structure of the contents of the map exactly matches the fields from T,
		// then we can convert the map to json, and then that json to a T instance.
		Map map = claims.get(field, Map.class);
		String json = GsonUtil.getGson().toJson(map);

		try {
			return GsonUtil.getGson().fromJson(json, clazz);
		} catch (JsonSyntaxException e) {
			throw new ApiException(ApiError.MALFORMED_ISSUER_REQUEST);
		}
	}

	/**
	 * Get the JWT issuer.
	 * @throws IllegalStateException if no JWT has yet been parsed
	 */
	public String getJwtIssuer() throws IllegalStateException {
		if (payload == null)
			throw new IllegalStateException("No JWT parsed yet");

		if (claims == null)
			return null;

		return claims.getIssuer();
	}

	/**
	 * Return the request that was present in the JWT's payload.
	 * @throws IllegalStateException if no JWT has yet been parsed
	 */
	public T getPayload() throws IllegalStateException {
		if (payload == null)
			throw new IllegalStateException("No JWT parsed yet");

		return payload;
	}
}
