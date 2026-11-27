package no.entur.abt.bob.mts7.test.mtb;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;

import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * Deliberately invalid Mobile Ticket Bundles (GET DATA responses), mostly with a field missing from the Issuer Signature Protected Header, and deliberately
 * invalid select application responses (with the valid bundle), with the expected outcome of verifying them. Shared by the tests of the card factories and of
 * the processors.
 * <p>
 * All bundles are signed by the {@linkplain #issuer} (where there is a signature), and the {@linkplain #internalAuthenticateResponse} is from the private key
 * of the token public key, so each case differs from a valid card only as described.
 */

public class InvalidMobileTicketBundles {

	public static final String RESOURCE = "/mts7/invalid-mobile-ticket-bundles.json";

	/**
	 * The expected outcome of a card which passes the verification.
	 */

	public static final String VERIFIED = "VERIFIED";

	/**
	 * The issuer key (as in the participant metadata) which signed the bundles.
	 */

	public static class Issuer {
		public long pid;
		public String kid;
		public String kty;
		public String crv;
		public String x;
		public String y;
	}

	public static class Case {
		public String name;
		public String description;

		/**
		 * Expected outcome of verifying the trust chain and the key pair: {@linkplain InvalidMobileTicketBundles#VERIFIED}, or the simple name of the class of
		 * the exception.
		 */
		public String trustChain;

		/**
		 * Expected outcome of verifying the key pair only: {@linkplain InvalidMobileTicketBundles#VERIFIED}, or the simple name of the class of the exception.
		 */
		public String keyPair;

		/**
		 * The GET DATA response, in hex, with the status word.
		 */
		public String getDataResponse;

		/**
		 * The select application response, in hex, with the status word, or null for the one which all cases share.
		 */
		public String selectApplicationResponse;

		/**
		 * The response to GET DATA of the application-related data (6E), in hex, with the status word, or null if none.
		 */

		public String applicationRelatedDataResponse;

		public byte[] applicationRelatedDataResponseApdu() {
			return applicationRelatedDataResponse == null ? null : hex(applicationRelatedDataResponse);
		}

		public byte[] getDataResponseApdu() {
			return hex(getDataResponse);
		}

		@Override
		public String toString() {
			return name;
		}
	}

	public String description;
	public Issuer issuer;
	public String selectApplicationResponse;
	public String challenge;
	public String internalAuthenticateResponse;
	public List<Case> cases;

	public static InvalidMobileTicketBundles load() throws IOException {
		try (InputStream in = InvalidMobileTicketBundles.class.getResourceAsStream(RESOURCE)) {
			return new ObjectMapper().readValue(in, InvalidMobileTicketBundles.class);
		}
	}

	public byte[] selectApplicationResponseApdu() {
		return hex(selectApplicationResponse);
	}

	/**
	 * @param c case
	 * @return the select application response of the case, or the one which all cases share
	 */

	public byte[] selectApplicationResponseApdu(Case c) {
		return c.selectApplicationResponse != null ? hex(c.selectApplicationResponse) : selectApplicationResponseApdu();
	}

	public byte[] challengeBytes() {
		return hex(challenge);
	}

	public byte[] internalAuthenticateResponseApdu() {
		return hex(internalAuthenticateResponse);
	}

	public static byte[] withoutStatusWord(byte[] responseApdu) {
		return Arrays.copyOf(responseApdu, responseApdu.length - 2);
	}

	private static byte[] hex(String hex) {
		return ByteArrayHexStringConverter.hexStringToByteArray(hex);
	}

}
