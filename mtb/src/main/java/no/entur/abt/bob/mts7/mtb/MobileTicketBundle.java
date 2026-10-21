package no.entur.abt.bob.mts7.mtb;

/**
 * Mobile Ticket Bundle (MTB), as read from the card using the 'get (next) data' command, or as created by an issuer.
 * <p>
 * A header object that provides the required metadata for the signature SHALL be attached to the Ticket Bundle by CBOR encoding each of the objects separately,
 * joining them in a CBOR array. This CBOR array is then used as input to the signing function, adding the output of the signing function as the last element to
 * the CBOR array. This forms the Issuer Signed Ticket Bundle.
 * <p>
 * The signed elements are kept in their CBOR encoded form, as they are needed to verify the issuer signature.
 */

public class MobileTicketBundle {

	/**
	 * The major version (v) defined by MTS1
	 */

	public static final String MAJOR_VERSION = "1";

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
	 * Create a Mobile Ticket Bundle with the current major version.
	 *
	 * @param signedElements                 the CBOR encoded elements which are signed by the issuer, starting with the Issuer Signature Protected Header
	 * @param signature                      the issuer signature over the signed elements
	 * @param issuerSignatureProtectedHeader the decoded Issuer Signature Protected Header
	 */

	public MobileTicketBundle(byte[][] signedElements, byte[] signature, IssuerSignatureProtectedHeader issuerSignatureProtectedHeader) {
		this(MAJOR_VERSION, signedElements, signature, issuerSignatureProtectedHeader);
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

	@Override
	public String toString() {
		StringBuilder elements = new StringBuilder();
		for (byte[] signedElement : signedElements) {
			if (elements.length() > 0) {
				elements.append(", ");
			}
			elements.append(toHexString(signedElement));
		}
		return "MobileTicketBundle [majorVersion=" + majorVersion + ", signedElements=[" + elements + "], signature=" + toHexString(signature)
				+ ", issuerSignatureProtectedHeader=" + issuerSignatureProtectedHeader + "]";
	}

	private static String toHexString(byte[] data) {
		StringBuilder sb = new StringBuilder(data.length * 2);
		for (byte b : data) {
			sb.append(String.format("%02X", b));
		}
		return sb.toString();
	}

}
