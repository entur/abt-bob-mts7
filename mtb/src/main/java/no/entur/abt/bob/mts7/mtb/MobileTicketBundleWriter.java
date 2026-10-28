package no.entur.abt.bob.mts7.mtb;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.text.Normalizer;
import java.util.regex.Pattern;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;

/**
 * Encode a {@linkplain MobileTicketBundle} and its parts, the counterpart of {@linkplain MobileTicketBundleParser}.
 * <p>
 * To issue a Mobile Ticket Bundle:
 * <ol>
 * <li>encode the Issuer Signature Protected Header using {@linkplain #writeIssuerSignatureProtectedHeader(IssuerSignatureProtectedHeader)}, and the Ticket
 * Bundle (for example {@linkplain #emptyTicketBundle()} for an ID MTB),</li>
 * <li>sign the output of {@linkplain #writeSignedData(byte[][])} for these elements,</li>
 * <li>encode the MTB Container using {@linkplain #write(MobileTicketBundle)}.</li>
 * </ol>
 * All output uses definite lengths and a fixed order of the parameters, so the encoding is stable byte for byte. This matters because the issuer signature
 * covers the encoded elements, and MTS1 section 2.3 requires the same representation to be used when signing as when assembling the Issuer Signed Ticket
 * Bundle. The CBOR generator is therefore used directly, as data binding writes maps with indefinite length. Text strings are NFC normalised, as recommended by
 * MTS1 section 2.3.
 * <p>
 * Instances are thread safe, so a single instance can be shared by all threads.
 */

public class MobileTicketBundleWriter {

	// MTS1 section 5: miv, iid and dsp are positive integers encoded as strings; the iid may be prefixed by '@' (MTS1 section 2.4, Issuer Identifier)
	protected static final Pattern POSITIVE_INTEGER = Pattern.compile("^[1-9][0-9]*$");
	protected static final Pattern ISSUER_IDENTIFIER = Pattern.compile("^@?[1-9][0-9]*$");

	// CBOR encoded empty map
	private static final byte[] EMPTY_MAP = new byte[] { (byte) 0xA0 };

	protected interface Content {
		void write(CBORGenerator generator) throws IOException;
	}

	/**
	 * @return the CBOR encoded empty Ticket Bundle, i.e. an empty map, which is the Ticket Bundle of an ID MTB
	 */

	public static byte[] emptyTicketBundle() {
		return EMPTY_MAP.clone();
	}

	// the factory has the default features, so that for example no self-describe tag is written
	protected final CBORFactory cborFactory = new CBORFactory();

	/**
	 * Encode the Issuer Signature Protected Header, with the parameters in the order alg, iid, kid, miv, exp, nbf, dsp, dsi and tpk. Parameters which are not
	 * set are left out.
	 *
	 * @param header the header
	 * @return the CBOR encoded header
	 * @throws IllegalArgumentException if the header does not conform to MTS1
	 */

	public byte[] writeIssuerSignatureProtectedHeader(IssuerSignatureProtectedHeader header) {
		validate(header);

		return encode(generator -> {
			generator.writeStartObject(header, 4 + count(header.getExp(), header.getNbf(), header.getDsp(), header.getDsi(), header.getTpk()));

			writeEntry(generator, "alg", header.getAlg());
			writeEntry(generator, "iid", header.getIid());
			writeEntry(generator, "kid", header.getKid());
			writeEntry(generator, "miv", header.getMiv());
			writeEntry(generator, "exp", header.getExp());
			writeEntry(generator, "nbf", header.getNbf());
			writeEntry(generator, "dsp", header.getDsp());
			writeEntry(generator, "dsi", header.getDsi());

			TokenPublicKey tpk = header.getTpk();
			if (tpk != null) {
				generator.writeFieldName("tpk");
				writeTokenPublicKey(generator, tpk);
			}

			generator.writeEndObject();
		});
	}

	/**
	 * Encode the data which is signed by the issuer: a CBOR array of the elements, each encoded as a byte string.
	 *
	 * @param signedElements the CBOR encoded elements, starting with the Issuer Signature Protected Header
	 * @return the input to the signing function
	 */

	public byte[] writeSignedData(byte[][] signedElements) {
		if (signedElements.length == 0) {
			throw new IllegalArgumentException("Expected at least one signed element");
		}
		return encode(generator -> writeByteStrings(generator, signedElements));
	}

	/**
	 * Encode the MTB Container (MTS1 section 2.6): a map with the major version (v) and the Issuer Signed Ticket Bundle (p).
	 *
	 * @param bundle the bundle
	 * @return the CBOR encoded MTB, in the Raw transport encoding
	 */

	public byte[] write(MobileTicketBundle bundle) {
		String majorVersion = bundle.getMajorVersion();
		if (majorVersion == null) {
			throw new IllegalArgumentException("Expected major version (v)");
		}
		byte[] signature = bundle.getSignature();
		if (signature == null || signature.length == 0) {
			throw new IllegalArgumentException("Expected signature");
		}
		byte[][] signedElements = bundle.getSignedElements();
		if (signedElements.length < 2) {
			throw new IllegalArgumentException("Expected the Issuer Signature Protected Header and the Ticket Bundle");
		}

		byte[][] elements = new byte[signedElements.length + 1][];
		System.arraycopy(signedElements, 0, elements, 0, signedElements.length);
		elements[signedElements.length] = signature;

		byte[] v = encode(generator -> writeString(generator, majorVersion));
		byte[] p = encode(generator -> writeByteStrings(generator, elements));

		return encode(generator -> {
			generator.writeStartObject(bundle, 2);
			generator.writeFieldName("v");
			generator.writeBinary(v);
			generator.writeFieldName("p");
			generator.writeBinary(p);
			generator.writeEndObject();
		});
	}

	protected void writeTokenPublicKey(CBORGenerator generator, TokenPublicKey tpk) throws IOException {
		if ("EC".equals(tpk.getKty())) {
			generator.writeStartObject(tpk, 4);
			writeEntry(generator, "kty", tpk.getKty());
			writeEntry(generator, "crv", tpk.getCrv());
			writeEntry(generator, "x", tpk.getX());
			writeEntry(generator, "y", tpk.getY());
		} else {
			generator.writeStartObject(tpk, 3);
			writeEntry(generator, "kty", tpk.getKty());
			writeEntry(generator, "n", tpk.getN());
			writeEntry(generator, "e", tpk.getE());
		}
		generator.writeEndObject();
	}

	/**
	 * Encode a single CBOR data item. The generator verifies that the number of items written matches the declared lengths.
	 *
	 * @param content writes the data item
	 * @return the encoded data item
	 */

	protected byte[] encode(Content content) {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try (CBORGenerator generator = cborFactory.createGenerator(out)) {
			content.write(generator);
		} catch (IOException e) {
			// writing to memory only fails if the content does not match the declared lengths
			throw new UncheckedIOException(e);
		}
		return out.toByteArray();
	}

	protected void validate(IssuerSignatureProtectedHeader header) {
		// MTS1 section 2.4
		require(header.getAlg(), "alg");
		require(header.getKid(), "kid");
		requirePattern(header.getIid(), "iid", ISSUER_IDENTIFIER);
		requirePattern(header.getMiv(), "miv", POSITIVE_INTEGER);

		if (header.getDid() != null) {
			throw new IllegalArgumentException("The Issuer Signature Protected Header must not contain a did parameter");
		}
		if (header.getDsp() != null) {
			requirePattern(header.getDsp(), "dsp", POSITIVE_INTEGER);
		}
		if (header.getDsi() != null && header.getDsp() == null) {
			throw new IllegalArgumentException("dsp must be set when dsi is set");
		}

		TokenPublicKey tpk = header.getTpk();
		if (tpk != null) {
			validate(tpk);
		}
	}

	protected void validate(TokenPublicKey tpk) {
		// MTS1 section 5: the schemas of the token public key do not allow additional properties
		if ("EC".equals(tpk.getKty())) {
			if (!"P-256".equals(tpk.getCrv())) {
				throw new IllegalArgumentException("Expected crv P-256 for tpk of kty EC");
			}
			require(tpk.getX(), "tpk x");
			require(tpk.getY(), "tpk y");
			if (tpk.getN() != null || tpk.getE() != null) {
				throw new IllegalArgumentException("Expected no n or e for tpk of kty EC");
			}
		} else if ("RSA".equals(tpk.getKty())) {
			require(tpk.getN(), "tpk n");
			require(tpk.getE(), "tpk e");
			if (tpk.getCrv() != null || tpk.getX() != null || tpk.getY() != null) {
				throw new IllegalArgumentException("Expected no crv, x or y for tpk of kty RSA");
			}
		} else {
			throw new IllegalArgumentException("Expected tpk of kty EC or RSA");
		}
	}

	private static void writeEntry(CBORGenerator generator, String key, String value) throws IOException {
		if (value != null) {
			generator.writeFieldName(key);
			writeString(generator, value);
		}
	}

	private static void writeString(CBORGenerator generator, String value) throws IOException {
		generator.writeString(Normalizer.normalize(value, Normalizer.Form.NFC));
	}

	private static void writeByteStrings(CBORGenerator generator, byte[][] elements) throws IOException {
		generator.writeStartArray(elements, elements.length);
		for (byte[] element : elements) {
			generator.writeBinary(element);
		}
		generator.writeEndArray();
	}

	private static int count(Object... values) {
		int count = 0;
		for (Object value : values) {
			if (value != null) {
				count++;
			}
		}
		return count;
	}

	private static void require(String value, String name) {
		if (value == null || value.isEmpty()) {
			throw new IllegalArgumentException("Expected " + name);
		}
	}

	private static void requirePattern(String value, String name, Pattern pattern) {
		require(value, name);
		if (!pattern.matcher(value).matches()) {
			throw new IllegalArgumentException("Unexpected " + name + " '" + value + "'");
		}
	}

}
