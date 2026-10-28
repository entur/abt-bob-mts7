package no.entur.abt.bob.mts7.core.pki;

import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import no.entur.abt.bob.mts7.core.UnableToConstructIccKeyException;
import no.entur.abt.bob.mts7.mtb.IssuerSignatureProtectedHeader;
import no.entur.abt.bob.mts7.mtb.MobileTicketBundleWriter;

public class IccPublicKeyBuilder {

	// thread safe, so shared by all builders
	protected static final MobileTicketBundleWriter WRITER = new MobileTicketBundleWriter();

	protected final IccPublicKeyFactory iccSignatureFactory;

	// the (CBOR encoded) elements of the signed data
	protected final List<byte[]> signedElements = new ArrayList<>();

	protected IssuerPublicKey issuerPublicKey;

	protected byte[] signature;

	protected IssuerSignatureProtectedHeader issuerSignatureProtectedHeader;

	public IccPublicKeyBuilder(IccPublicKeyFactory factory) {
		this.iccSignatureFactory = factory;
	}

	public boolean canBuild() {
		if (signedElements.isEmpty()) {
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

		signature = null;
		issuerPublicKey = null;
		issuerSignatureProtectedHeader = null;
	}

	/**
	 * Verify the issuer signature, and create the ICC public key.
	 *
	 * @return the ICC public key
	 * @throws SignatureException               if the issuer signature is not valid
	 * @throws UnableToConstructIccKeyException if the ICC public key could not be created
	 */

	public IccPublicKey build() throws SignatureException, UnableToConstructIccKeyException {
		byte[] data = getSignedData();

		if (!issuerPublicKey.verify(data, signature)) {
			throw new SignatureException("Issuer signature is not valid");
		}

		return iccSignatureFactory.create(issuerSignatureProtectedHeader);
	}

	/**
	 * The signed data: a CBOR array of the elements, each encoded as a byte string.
	 *
	 * @return the encoded signed data
	 */

	protected byte[] getSignedData() {
		return WRITER.writeSignedData(signedElements.toArray(new byte[0][]));
	}

}
