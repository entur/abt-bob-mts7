package no.entur.abt.bob.mts7.core.pki;

import no.entur.abt.bob.mts7.mtb.TokenPublicKey;

/**
 * The signature algorithms of MTS1, as named in JWA (RFC 7518).
 * <p>
 * In the Issuer Signature Protected Header, <code>alg</code> is the algorithm of the issuer signature (MTS1, section 2.4): ES256 (primary) or RS256 (fallback).
 * It says nothing about the card: the algorithm of the signatures of the card follows from the type of its public key (<code>tpk</code>), which is EC (P-256)
 * or RSA (MTS1, section 5).
 */

public final class Mts1Algorithms {

	/**
	 * ECDSA with P-256 and SHA-256, the primary algorithm of the issuer signature
	 */

	public static final String ES256 = "ES256";

	/**
	 * RSASSA-PKCS1-v1_5 with SHA-256, the fallback algorithm of the issuer signature
	 */

	public static final String RS256 = "RS256";

	private Mts1Algorithms() {
	}

	/**
	 * @param alg the algorithm of the issuer signature, as in the Issuer Signature Protected Header
	 * @return whether the algorithm is one of those in MTS1
	 */

	public static boolean isIssuerSignatureAlgorithm(String alg) {
		return ES256.equals(alg) || RS256.equals(alg);
	}

	/**
	 * The algorithm of the signatures of the card, from the type of its public key.
	 *
	 * @param tpk the token public key of the card, or null
	 * @return ES256 for an EC key, RS256 for an RSA key, or null if the key is missing or of another type
	 */

	public static String getTokenAlgorithm(TokenPublicKey tpk) {
		if (tpk != null) {
			if ("EC".equals(tpk.getKty())) {
				return ES256;
			}
			if ("RSA".equals(tpk.getKty())) {
				return RS256;
			}
		}
		return null;
	}

}
