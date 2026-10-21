package no.entur.abt.bob.mts7.mtb;

import java.io.IOException;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

/**
 * Parse the CBOR encoded Mobile Ticket Bundle (the output of the 'get (next) data' command) into a {@linkplain MobileTicketBundle}.
 * <p>
 * Instances are thread safe, so a single instance can be shared by all threads. Instances are also cheap to create, as long as the CBOR mapper is shared.
 */

public class MobileTicketBundleParser {

	@JsonIgnoreProperties(ignoreUnknown = true)
	static class EncodedMobileTicketBundle {

		// CBOR encoded major version (text string)
		public byte[] v;

		// CBOR encoded Issuer Signed Ticket Bundle (array of byte strings)
		public byte[] p;
	}

	protected final CBORMapper cborMapper;

	protected final ObjectReader mobileTicketBundleReader;
	protected final ObjectReader majorVersionReader;
	protected final ObjectReader issuerSignedTicketBundleReader;
	protected final ObjectReader protectedHeaderReader;

	public MobileTicketBundleParser() {
		this(new CBORMapper());
	}

	public MobileTicketBundleParser(CBORMapper cborMapper) {
		this.cborMapper = cborMapper;

		this.mobileTicketBundleReader = cborMapper.readerFor(EncodedMobileTicketBundle.class);
		this.majorVersionReader = cborMapper.readerFor(String.class);
		this.issuerSignedTicketBundleReader = cborMapper.readerFor(byte[][].class);
		this.protectedHeaderReader = cborMapper.readerFor(IssuerSignatureProtectedHeader.class);
	}

	public CBORMapper getCborMapper() {
		return cborMapper;
	}

	public MobileTicketBundle parse(byte[] content) throws IOException {
		EncodedMobileTicketBundle encoded = mobileTicketBundleReader.readValue(content);

		if (encoded.p == null) {
			throw new IOException("Expected Issuer Signed Ticket Bundle (p)");
		}

		String majorVersion = null;
		if (encoded.v != null) {
			majorVersion = majorVersionReader.readValue(encoded.v);
		}

		byte[][] elements = issuerSignedTicketBundleReader.readValue(encoded.p);
		if (elements == null || elements.length < 2) {
			throw new IOException("Expected at least one signed element and the signature in the Issuer Signed Ticket Bundle");
		}

		byte[][] signedElements = new byte[elements.length - 1][];
		System.arraycopy(elements, 0, signedElements, 0, signedElements.length);

		byte[] signature = elements[elements.length - 1];

		return new MobileTicketBundle(majorVersion, signedElements, signature, parseIssuerSignatureProtectedHeader(signedElements));
	}

	/**
	 * Find the Issuer Signature Protected Header among the signed elements.
	 *
	 * @param signedElements CBOR encoded elements
	 * @return the first element which is an Issuer Signature Protected Header, or null if none
	 * @throws IOException if an element could not be parsed
	 */

	protected IssuerSignatureProtectedHeader parseIssuerSignatureProtectedHeader(byte[][] signedElements) throws IOException {
		for (byte[] element : signedElements) {
			IssuerSignatureProtectedHeader header = protectedHeaderReader.readValue(element);

			// To be able to distinguish between the Issuer Signature and the Device Signature (see section 2.5) header, the Issuer Signature Protected
			// Header MUST NOT contain a did parameter.
			if (header.isDeviceSignatureProtectedHeader()) {
				continue;
			}

			if (header.getKid() == null || header.getIid() == null) {
				continue;
			}

			return header;
		}
		return null;
	}

}
