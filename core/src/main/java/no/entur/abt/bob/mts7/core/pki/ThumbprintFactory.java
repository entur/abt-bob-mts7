package no.entur.abt.bob.mts7.core.pki;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Map;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;

import no.entur.abt.bob.mts7.core.UnableToConstructThumbprintKeyException;

/**
 * Create thumbprint according to https://www.rfc-editor.org/rfc/rfc7638.html and BoB
 *
 */

public class ThumbprintFactory {

	protected final Provider provider;
	protected final MessageDigest messageDigest;
	protected final JsonFactory jsonFactory;

	public ThumbprintFactory(Provider provider) throws NoSuchAlgorithmException {
		this(provider, "SHA-256");
	}

	public ThumbprintFactory(Provider provider, String digestAlgorithm) throws NoSuchAlgorithmException {
		this.provider = provider;

		if (digestAlgorithm == null) {
			throw new IllegalStateException();
		}

		if (provider == null) {
			this.messageDigest = MessageDigest.getInstance(digestAlgorithm);
		} else {
			this.messageDigest = MessageDigest.getInstance(digestAlgorithm, provider);
		}

		this.jsonFactory = new JsonFactory();
	}

	public byte[] create(Map<String, Object> fields) throws UnableToConstructThumbprintKeyException {

		//
		// The Issuer Signature Protected Header SHALL include the following parameters:
		// • alg – Signature Algorithm (string)
		// • iid – Issuer Identifier (string)
		// • kid – Key identifier (string)
		// • miv – Mobile Ticket Specification minor version number (number)
		// o This document defines minor version 6
		//
		// To be able to distinguish between the Issuer Signature and the Device Signature (see section 2.5)
		// header, the Issuer Signature Protected Header MUST NOT contain a did parameter.
		//
		// The Issuer Signature Protected Header MAY include the following parameters:
		// • exp – Signature Expiry (timestamp in ISO 8601:2004 profile basic format, see 2.2 in (MTS8), string)
		// • nbf – Signature Inception (timestamp in ISO 8601:2004 profile basic format, see 2.2 in (MTS8), string)
		// • dsp – Device Signature Provider (string)
		// • dsi – Device Signature Identifier (string)
		// • tpk – Token Public Key (object)
		//

		Map<String, Object> tpk = (Map<String, Object>) fields.get("tpk");

		String algorithm = (String) fields.get("alg");

		byte[] message = null;

		if (algorithm.equals("RS256")) {
			message = createRSAMessage(tpk);
		} else if (algorithm.equals("ES256")) {
			message = createECMessage(tpk);
		} else {
			throw new UnableToConstructThumbprintKeyException(algorithm);
		}

		byte[] digest = messageDigest.digest(message);

		byte[] firstHalfOfDigest = new byte[digest.length / 2];
		System.arraycopy(digest, 0, firstHalfOfDigest, 0, firstHalfOfDigest.length);
		return firstHalfOfDigest;
	}

	private byte[] createECMessage(Map<String, Object> tpk) throws UnableToConstructThumbprintKeyException {
		ByteArrayOutputStream bout = new ByteArrayOutputStream();

		// RFC-7638:
		// the required members for an elliptic curve public key ... in lexicographic order
		// "crv"
		// "kty"
		// "x"
		// "y"

		try {
			JsonGenerator generator = jsonFactory.createGenerator(bout);

			try {
				generator.writeStartObject();

				generator.writeStringField("crv", (String) tpk.get("crv"));
				generator.writeStringField("kty", (String) tpk.get("kty"));
				generator.writeStringField("x", (String) tpk.get("x"));
				generator.writeStringField("y", (String) tpk.get("y"));

				generator.writeEndObject();
			} finally {
				generator.close();
			}
		} catch (Exception e) {
			throw new UnableToConstructThumbprintKeyException(e);
		}
		return bout.toByteArray();
	}

	private byte[] createRSAMessage(Map<String, Object> tpk) throws UnableToConstructThumbprintKeyException {
		ByteArrayOutputStream bout = new ByteArrayOutputStream();

		// RFC-7638:
		// The required members for an RSA public key, in lexicographic order, are:
		// - e
		// - kty
		// - n

		try {
			JsonGenerator generator = jsonFactory.createGenerator(bout);

			try {
				generator.writeStartObject();

				generator.writeStringField("e", (String) tpk.get("e"));
				generator.writeStringField("kty", (String) tpk.get("kty"));
				generator.writeStringField("n", (String) tpk.get("n"));

				generator.writeEndObject();
			} finally {
				generator.close();
			}
		} catch (Exception e) {
			throw new UnableToConstructThumbprintKeyException(e);
		}

		return bout.toByteArray();
	}

}
