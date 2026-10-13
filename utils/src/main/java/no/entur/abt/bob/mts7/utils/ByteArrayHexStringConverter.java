package no.entur.abt.bob.mts7.utils;

public class ByteArrayHexStringConverter {

	/**
	 * Utility method to convert a byte array to a hexadecimal string.
	 *
	 * @param data Bytes to convert
	 * @return String, containing hexadecimal representation.
	 */
	public static String toHexString(byte[] data) {
		return toHexString(data, "%02X");
	}

	/**
	 * Utility method to convert a byte array to a hexadecimal string.
	 *
	 * @param data   Bytes to convert
	 * @param offset offset
	 * @param length length
	 *
	 * @return String, containing hexadecimal representation.
	 */
	public static String toHexString(byte[] data, int offset, int length) {
		return toHexString(data, offset, length, "%02X");
	}

	public static String toHexString(byte[] data, int offset, int length, String format) {
		StringBuilder sb = new StringBuilder();
		if (data != null) {
			for (int i = offset; i < offset + length; i++) {
				sb.append(String.format(format, data[i]));
			}
		}
		return sb.toString();
	}

	public static String toHexString(byte[] data, String format) {
		StringBuilder sb = new StringBuilder();
		if (data != null) {
			for (byte b : data) {
				sb.append(String.format(format, b));
			}
		}
		return sb.toString();
	}

	public static String byteToHexString(byte b) {
		return String.format("%02X", b);
	}

	public static String byteArrayToSpacedHexString(byte[] data, int offset, int length) {
		String s = toHexString(data, offset, length, "%02X ");
		if (s.length() > 0) {
			return s.substring(0, s.length() - 1);
		}
		return s;
	}

	public static String byteArrayToSpacedHexString(byte[] data) {
		String s = toHexString(data, "%02X ");
		if (s.length() > 0) {
			return s.substring(0, s.length() - 1);
		}
		return s;
	}

	/**
	 * Utility method to convert a hexadecimal string to a byte array.
	 *
	 * @param s hexadecimal string, two characters (0-9, a-f or A-F) for each byte
	 * @return the bytes
	 * @throws IllegalArgumentException if the length is odd, or there is a character which is not a hexadecimal digit
	 */

	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		if (len % 2 != 0) {
			throw new IllegalArgumentException("Expected an even number of hexadecimal digits, got " + len);
		}
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((hexDigit(s, i) << 4) + hexDigit(s, i + 1));
		}
		return data;
	}

	private static int hexDigit(String s, int index) {
		char c = s.charAt(index);
		if (c >= '0' && c <= '9') {
			return c - '0';
		}
		if (c >= 'A' && c <= 'F') {
			return c - 'A' + 10;
		}
		if (c >= 'a' && c <= 'f') {
			return c - 'a' + 10;
		}
		throw new IllegalArgumentException("Expected hexadecimal digit at index " + index + ", got '" + c + "'");
	}

}
