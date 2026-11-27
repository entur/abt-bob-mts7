package no.entur.abt.bob.mts7.mtb;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Decodes the Issuer Signed Ticket Bundle (p): a CBOR array of byte strings, the last of which is the issuer signature.
 * <p>
 * The signed data is the same array without the signature. MTS1 (section 2.3) recommends the one-byte representation of the array, but requires decoders to
 * detect the representation which is used, as the issuer signs the array in the same representation as it assembles it. So the signed data is rebuilt in the
 * representation of the array, with the elements exactly as encoded, rather than encoded anew.
 */

class IssuerSignedTicketBundleDecoder {

	private static final int MAJOR_TYPE_BYTE_STRING = 2;
	private static final int MAJOR_TYPE_ARRAY = 4;
	private static final int INDEFINITE = 31;
	private static final int BREAK = 0xFF;
	private static final int NULL = 0xF6;

	private final byte[] buffer;
	private int position;

	private byte[][] elements;
	private byte[] signedData;

	IssuerSignedTicketBundleDecoder(byte[] buffer) {
		this.buffer = buffer;
	}

	/**
	 * @return the content of each byte string of the array
	 */

	byte[][] getElements() {
		return elements;
	}

	/**
	 * @return the array without its last element (the signature), in the representation of the array
	 */

	byte[] getSignedData() {
		return signedData;
	}

	void decode() throws IOException {
		int initial = readByte();
		if ((initial >> 5) != MAJOR_TYPE_ARRAY) {
			throw new IOException("Expected an array as the Issuer Signed Ticket Bundle");
		}
		int additional = initial & 0x1F;
		boolean indefinite = additional == INDEFINITE;
		long count = indefinite ? -1 : readArgument(additional);

		List<byte[]> contents = new ArrayList<>();
		List<int[]> encodings = new ArrayList<>();
		while (true) {
			if (indefinite) {
				if (peekByte() == BREAK) {
					position++;
					break;
				}
			} else if (contents.size() == count) {
				break;
			}
			int start = position;
			contents.add(readByteString());
			encodings.add(new int[] { start, position });
		}

		if (contents.size() < 2) {
			throw new IOException("Expected at least one signed element and the signature in the Issuer Signed Ticket Bundle");
		}

		this.elements = contents.toArray(new byte[0][]);

		int signedCount = contents.size() - 1;
		ByteArrayOutputStream out = new ByteArrayOutputStream(buffer.length);
		if (indefinite) {
			out.write(0x9F);
		} else {
			writeHeader(out, MAJOR_TYPE_ARRAY, signedCount, additional);
		}
		for (int i = 0; i < signedCount; i++) {
			int[] encoding = encodings.get(i);
			out.write(buffer, encoding[0], encoding[1] - encoding[0]);
		}
		if (indefinite) {
			out.write(BREAK);
		}
		this.signedData = out.toByteArray();
	}

	private byte[] readByteString() throws IOException {
		int initial = readByte();
		if (initial == NULL) {
			throw new IOException("Expected byte strings in the Issuer Signed Ticket Bundle, not null");
		}
		if ((initial >> 5) != MAJOR_TYPE_BYTE_STRING) {
			throw new IOException("Expected byte strings in the Issuer Signed Ticket Bundle");
		}
		int additional = initial & 0x1F;
		if (additional != INDEFINITE) {
			return readBytes(readArgument(additional));
		}
		// chunks of definite length byte strings, until break
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		while (true) {
			int chunk = readByte();
			if (chunk == BREAK) {
				return out.toByteArray();
			}
			if ((chunk >> 5) != MAJOR_TYPE_BYTE_STRING || (chunk & 0x1F) == INDEFINITE) {
				throw new IOException("Expected byte string chunks in an indefinite length byte string");
			}
			byte[] bytes = readBytes(readArgument(chunk & 0x1F));
			out.write(bytes, 0, bytes.length);
		}
	}

	private long readArgument(int additional) throws IOException {
		if (additional < 24) {
			return additional;
		}
		int length;
		switch (additional) {
		case 24:
			length = 1;
			break;
		case 25:
			length = 2;
			break;
		case 26:
			length = 4;
			break;
		case 27:
			length = 8;
			break;
		default:
			throw new IOException("Unexpected additional information " + additional);
		}
		long value = 0;
		for (int i = 0; i < length; i++) {
			value = (value << 8) | readByte();
		}
		if (value < 0) {
			throw new IOException("Length out of range");
		}
		return value;
	}

	private byte[] readBytes(long length) throws IOException {
		if (length > buffer.length - position) {
			throw new IOException("Truncated Issuer Signed Ticket Bundle");
		}
		byte[] bytes = new byte[(int) length];
		System.arraycopy(buffer, position, bytes, 0, bytes.length);
		position += bytes.length;
		return bytes;
	}

	private int readByte() throws IOException {
		if (position >= buffer.length) {
			throw new IOException("Truncated Issuer Signed Ticket Bundle");
		}
		return buffer[position++] & 0xFF;
	}

	private int peekByte() throws IOException {
		if (position >= buffer.length) {
			throw new IOException("Truncated Issuer Signed Ticket Bundle");
		}
		return buffer[position] & 0xFF;
	}

	/**
	 * Write the header of a data item with the same width of the argument as in the original.
	 */

	private static void writeHeader(ByteArrayOutputStream out, int majorType, long value, int additional) {
		int type = majorType << 5;
		if (additional < 24) {
			// value is smaller than the original, which fitted in the initial byte
			out.write(type | (int) value);
			return;
		}
		int length = 1 << (additional - 24);
		out.write(type | additional);
		for (int i = length - 1; i >= 0; i--) {
			out.write((int) (value >>> (8 * i)) & 0xFF);
		}
	}
}
