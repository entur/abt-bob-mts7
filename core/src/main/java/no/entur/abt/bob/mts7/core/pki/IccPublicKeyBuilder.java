package no.entur.abt.bob.mts7.core.pki;

import java.io.ByteArrayOutputStream;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import no.entur.abt.bob.mts7.core.UnableToConstructIccKeyException;

/**
 * Builder for the ICC public key, which verifies that the key is vouched for by the issuer.
 *
 * <p>
 * The issuer signs the elements which precede the signature in the issuer signed ticket bundle. Each element is a (CBOR encoded) object, which is itself
 * encoded as a CBOR byte string. The input to the issuer signature function is a CBOR array of these byte strings.
 */

public class IccPublicKeyBuilder {

	protected static final int CBOR_MAJOR_TYPE_BYTE_STRING = 2;
	protected static final int CBOR_MAJOR_TYPE_ARRAY = 4;

	protected final IccPublicKeyFactory iccSignatureFactory;

	protected List<byte[]> signedElements = new ArrayList<>();

	protected IssuerPublicKey issuerPublicKey;

	protected byte[] signature;

	protected Map<String, Object> issuerSignatureProtectedHeader;

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
	 * @param buffer buffer containing the (CBOR encoded) element
	 * @param offset offset of the element
	 * @param length length of the element
	 * @return this instance
	 */

	public IccPublicKeyBuilder withSignedData(byte[] buffer, int offset, int length) {
		byte[] element = new byte[length];
		System.arraycopy(buffer, offset, element, 0, length);

		signedElements.add(element);
		return this;
	}

	public IccPublicKeyBuilder withIssuerPublicKey(IssuerPublicKey issuerPublicKey) {
		this.issuerPublicKey = issuerPublicKey;
		return this;
	}

	public IccPublicKeyBuilder withIssuerSignatureProtectedHeader(Map<String, Object> issuerSignatureProtectedHeader) {
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
	 * @throws IllegalStateException            if there is not enough data (see {@linkplain #canBuild()})
	 */

	public IccPublicKey build() throws SignatureException, UnableToConstructIccKeyException {
		if (!canBuild()) {
			throw new IllegalStateException("Not enough data for verifying the issuer signature");
		}

		if (!issuerPublicKey.verify(getSignedData(), signature)) {
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
		ByteArrayOutputStream out = new ByteArrayOutputStream();

		writeHead(out, CBOR_MAJOR_TYPE_ARRAY, signedElements.size());
		for (byte[] element : signedElements) {
			writeHead(out, CBOR_MAJOR_TYPE_BYTE_STRING, element.length);
			out.write(element, 0, element.length);
		}

		return out.toByteArray();
	}

	/**
	 * Write the initial byte(s) of a CBOR data item, using the shortest encoding of the argument (which is the length).
	 */

	protected static void writeHead(ByteArrayOutputStream out, int majorType, int length) {
		int type = majorType << 5;

		if (length < 24) {
			out.write(type | length);
		} else if (length <= 0xFF) {
			out.write(type | 24);
			out.write(length);
		} else if (length <= 0xFFFF) {
			out.write(type | 25);
			out.write(length >> 8);
			out.write(length);
		} else {
			out.write(type | 26);
			out.write(length >> 24);
			out.write(length >> 16);
			out.write(length >> 8);
			out.write(length);
		}
	}

}
