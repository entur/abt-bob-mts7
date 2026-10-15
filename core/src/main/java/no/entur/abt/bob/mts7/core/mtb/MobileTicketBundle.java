package no.entur.abt.bob.mts7.core.mtb;

/**
 * Mobile Ticket Bundle (MTB), as read from the card using the 'get (next) data' command.
 * <p>
 * A header object that provides the required metadata for the signature SHALL be attached to the Ticket Bundle by CBOR encoding each of the objects separately,
 * joining them in a CBOR array. This CBOR array is then used as input to the signing function, adding the output of the signing function as the last element to
 * the CBOR array. This forms the Issuer Signed Ticket Bundle.
 * <p>
 * The signed elements are kept in their CBOR encoded form, as they are needed to verify the issuer signature.
 */

public class MobileTicketBundle {

	private final String majorVersion;

	private final byte[][] signedElements;

	private final byte[] signature;

	private final IssuerSignatureProtectedHeader issuerSignatureProtectedHeader;

	public MobileTicketBundle(String majorVersion, byte[][] signedElements, byte[] signature, IssuerSignatureProtectedHeader issuerSignatureProtectedHeader) {
		this.majorVersion = majorVersion;
		this.signedElements = signedElements;
		this.signature = signature;
		this.issuerSignatureProtectedHeader = issuerSignatureProtectedHeader;
	}

	/**
	 * @return the major version (v), or null if not present
	 */

	public String getMajorVersion() {
		return majorVersion;
	}

	/**
	 * @return the CBOR encoded elements which were signed by the issuer, i.e. all elements of the Issuer Signed Ticket Bundle except the signature
	 */

	public byte[][] getSignedElements() {
		return signedElements;
	}

	/**
	 * @return the issuer signature, i.e. the last element of the Issuer Signed Ticket Bundle
	 */

	public byte[] getSignature() {
		return signature;
	}

	/**
	 * @return the Issuer Signature Protected Header, or null if none of the signed elements is an Issuer Signature Protected Header
	 */

	public IssuerSignatureProtectedHeader getIssuerSignatureProtectedHeader() {
		return issuerSignatureProtectedHeader;
	}

	public boolean hasIssuerSignatureProtectedHeader() {
		return issuerSignatureProtectedHeader != null;
	}

}
