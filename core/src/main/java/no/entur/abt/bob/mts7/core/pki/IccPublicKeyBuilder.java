package no.entur.abt.bob.mts7.core.pki;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.NoSuchAlgorithmMts7Exception;
import no.entur.abt.bob.mts7.core.NonCompliantIccKeyInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.TrustChainInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.UnableToConstructIccKeyException;
import no.entur.abt.bob.mts7.core.UnableToConstructIssuerKeyException;
import no.entur.abt.bob.mts7.mtb.IssuerSignatureProtectedHeader;
import no.entur.abt.bob.mts7.mtb.MobileTicketBundleWriter;

public class IccPublicKeyBuilder {

	// thread safe, so shared by all builders
	protected static final MobileTicketBundleWriter WRITER = new MobileTicketBundleWriter();

	protected final IccPublicKeyFactory iccSignatureFactory;

	// the (CBOR encoded) elements of the signed data
	protected final List<byte[]> signedElements = new ArrayList<>();

	// the signed data as encoded in the bundle, which takes precedence over the elements
	protected byte[] encodedSignedData;

	protected IssuerPublicKey issuerPublicKey;

	protected byte[] signature;

	protected IssuerSignatureProtectedHeader issuerSignatureProtectedHeader;

	public IccPublicKeyBuilder(IccPublicKeyFactory factory) {
		this.iccSignatureFactory = factory;
	}

	public boolean canBuild() {
		if (signedElements.isEmpty() && encodedSignedData == null) {
			return false;
		}
		if (issuerPublicKey == null) {
			return false;
		}
		if (signature == null) {
			return false;
		}
		if (issuerSignatureProtectedHeader == null) {
			return false;
		}
		return true;
	}

	/**
	 * Add an element of the signed data, i.e. one of the elements which precede the signature in the issuer signed ticket bundle. Elements must be added in the
	 * order in which they appear.
	 *
	 * <p>
	 * The issuer signs a CBOR array of the elements, each encoded as a byte string.
	 *
	 * @param buffer buffer containing the (CBOR encoded) element
	 * @param offset offset of the element
	 * @param length length of the element
	 * @return this instance
	 */

	public IccPublicKeyBuilder withSignedData(byte[] buffer, int offset, int length) {
		signedElements.add(Arrays.copyOfRange(buffer, offset, offset + length));
		return this;
	}

	/**
	 * Set the signed data as encoded in the bundle (see {@linkplain no.entur.abt.bob.mts7.mtb.MobileTicketBundle#getSignedData()}). The issuer signs the
	 * elements in the representation in which it assembles the bundle (MTS1 section 2.3), which need not be the recommended one which
	 * {@linkplain #withSignedData(byte[], int, int)} gives. This takes precedence over the elements.
	 *
	 * @param signedData the CBOR encoded array of the signed elements
	 * @return this instance
	 */

	public IccPublicKeyBuilder withEncodedSignedData(byte[] signedData) {
		this.encodedSignedData = signedData;
		return this;
	}

	public IccPublicKeyBuilder withIssuerPublicKey(IssuerPublicKey issuerPublicKey) {
		this.issuerPublicKey = issuerPublicKey;
		return this;
	}

	public IccPublicKeyBuilder withIssuerSignatureProtectedHeader(IssuerSignatureProtectedHeader issuerSignatureProtectedHeader) {
		this.issuerSignatureProtectedHeader = issuerSignatureProtectedHeader;
		return this;
	}

	public IccPublicKeyBuilder withSignature(byte[] signature) {
		this.signature = signature;
		return this;
	}

	public void reset() {
		signedElements.clear();
		encodedSignedData = null;

		signature = null;
		issuerPublicKey = null;
		issuerSignatureProtectedHeader = null;
	}

	/**
	 * Verify the issuer signature, and create the ICC public key.
	 * <p>
	 * The algorithm of the issuer signature (<code>alg</code> in the header) is checked first: it must be one of those in MTS1 (ES256 or RS256), and match the
	 * issuer key. A card which is not as in the specification is to blame, whatever happens on our side when verifying.
	 *
	 * @return the ICC public key
	 * @throws TrustChainInvalidCardMts7Exception         if the issuer signature is not valid, or its algorithm does not match the issuer key (a problem on the
	 *                                                    card side)
	 * @throws NonCompliantIccKeyInvalidCardMts7Exception if the ICC public key could not be created from the certificate of the card (a problem on the card
	 *                                                    side)
	 * @throws InvalidCardMts7Exception                   if the algorithm of the issuer signature is missing or not as in MTS1 (a problem on the card side).
	 *                                                    This is also the superclass of the above.
	 * @throws NoSuchAlgorithmMts7Exception               if a signature algorithm is not available from the security provider (a problem on our side)
	 * @throws UnableToConstructIssuerKeyException        if the issuer key is not accepted by the security provider (a problem on our side)
	 */

	public IccPublicKey build()
			throws InvalidCardMts7Exception, NoSuchAlgorithmMts7Exception, UnableToConstructIssuerKeyException, UnableToConstructIccKeyException {
		checkAlgorithm();

		byte[] data = getSignedData();

		issuerPublicKey.verify(data, signature);

		return iccSignatureFactory.create(issuerSignatureProtectedHeader);
	}

	/**
	 * Check the algorithm of the issuer signature in the header of the card, before anything which could fail on our side.
	 *
	 * @throws InvalidCardMts7Exception           if the algorithm is missing or not as in MTS1 (a problem on the card side)
	 * @throws TrustChainInvalidCardMts7Exception if the algorithm does not match the issuer key (a problem on the card side)
	 */

	protected void checkAlgorithm() throws InvalidCardMts7Exception {
		String alg = issuerSignatureProtectedHeader.getAlg();
		if (!Mts1Algorithms.isIssuerSignatureAlgorithm(alg)) {
			throw new InvalidCardMts7Exception("Issuer signature algorithm " + alg + " is not " + Mts1Algorithms.ES256 + " or " + Mts1Algorithms.RS256);
		}
		String expected = issuerPublicKey.getJwsAlgorithm();
		if (expected != null && !expected.equals(alg)) {
			throw new TrustChainInvalidCardMts7Exception("Issuer signature algorithm " + alg + " does not match issuer public key " + issuerPublicKey.getKid()
					+ " of participant " + issuerPublicKey.getPid() + " (" + expected + ")");
		}
	}

	/**
	 * The signed data: a CBOR array of the elements, each encoded as a byte string.
	 *
	 * @return the encoded signed data
	 */

	protected byte[] getSignedData() {
		if (encodedSignedData != null) {
			return encodedSignedData;
		}
		return WRITER.writeSignedData(signedElements.toArray(new byte[0][]));
	}

}
