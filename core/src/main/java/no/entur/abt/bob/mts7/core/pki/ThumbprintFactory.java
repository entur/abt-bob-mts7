package no.entur.abt.bob.mts7.core.pki;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;

import no.entur.abt.bob.mts7.core.exception.NonCompliantIccKeyInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.exception.UnableToConstructThumbprintKeyException;
import no.entur.abt.bob.mts7.mtb.IssuerSignatureProtectedHeader;
import no.entur.abt.bob.mts7.mtb.TokenPublicKey;

/**
 * Create thumbprint according to https://www.rfc-editor.org/rfc/rfc7638.html and BoB
 * <p>
 * Instances are thread safe, so a single instance can be shared by all threads.
 */

public class ThumbprintFactory {

	protected final Provider provider;
	protected final String digestAlgorithm;
	protected final JsonFactory jsonFactory;

	public ThumbprintFactory(Provider provider) throws NoSuchAlgorithmException {
		this(provider, "SHA-256");
	}

	public ThumbprintFactory(Provider provider, String digestAlgorithm) throws NoSuchAlgorithmException {
		this.provider = provider;

		if (digestAlgorithm == null) {
			throw new IllegalStateException();
		}
		this.digestAlgorithm = digestAlgorithm;

		// a digest is stateful, so each thread needs its own (and they are cheap to create), but check that the algorithm is available now
		newMessageDigest();

		this.jsonFactory = new JsonFactory();
	}

	private MessageDigest newMessageDigest() throws NoSuchAlgorithmException {
		if (provider == null) {
			return MessageDigest.getInstance(digestAlgorithm);
		}
		return MessageDigest.getInstance(digestAlgorithm, provider);
	}

	/**
	 * Create the thumbprint of the public key of the card.
	 *
	 * @param header the Issuer Signature Protected Header of the card
	 * @return the thumbprint
	 * @throws NonCompliantIccKeyInvalidCardMts7Exception if the token public key of the card is missing or of a type which is not in MTS1 (a problem on the
	 *                                                    card side)
	 * @throws UnableToConstructThumbprintKeyException    if the thumbprint could not be created for a valid key (a problem with the verifier)
	 */

	public byte[] create(IssuerSignatureProtectedHeader header) throws NonCompliantIccKeyInvalidCardMts7Exception, UnableToConstructThumbprintKeyException {
		TokenPublicKey tpk = header.getTpk();
		if (tpk == null) {
			throw new NonCompliantIccKeyInvalidCardMts7Exception("Missing token public key");
		}

		// by the type of the key, not alg in the header, which is the algorithm of the issuer signature
		byte[] message;

		String algorithm = Mts1Algorithms.getTokenAlgorithm(tpk);
		if (Mts1Algorithms.RS256.equals(algorithm)) {
			message = createRSAMessage(tpk);
		} else if (Mts1Algorithms.ES256.equals(algorithm)) {
			message = createECMessage(tpk);
		} else {
			throw new NonCompliantIccKeyInvalidCardMts7Exception("Unknown key type " + tpk.getKty());
		}

		byte[] digest;
		try {
			digest = newMessageDigest().digest(message);
		} catch (NoSuchAlgorithmException e) {
			throw new UnableToConstructThumbprintKeyException(e);
		}

		byte[] firstHalfOfDigest = new byte[digest.length / 2];
		System.arraycopy(digest, 0, firstHalfOfDigest, 0, firstHalfOfDigest.length);
		return firstHalfOfDigest;
	}

	private byte[] createECMessage(TokenPublicKey tpk) throws UnableToConstructThumbprintKeyException {
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

				generator.writeStringField("crv", tpk.getCrv());
				generator.writeStringField("kty", tpk.getKty());
				generator.writeStringField("x", tpk.getX());
				generator.writeStringField("y", tpk.getY());

				generator.writeEndObject();
			} finally {
				generator.close();
			}
		} catch (Exception e) {
			throw new UnableToConstructThumbprintKeyException(e);
		}
		return bout.toByteArray();
	}

	private byte[] createRSAMessage(TokenPublicKey tpk) throws UnableToConstructThumbprintKeyException {
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

				generator.writeStringField("e", tpk.getE());
				generator.writeStringField("kty", tpk.getKty());
				generator.writeStringField("n", tpk.getN());

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
