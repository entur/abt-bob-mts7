package no.entur.abt.bob.mts7.mtb;

final class Hex {

	private Hex() {
	}

	static byte[] decode(String hex) {
		String value = hex.replaceAll("\\s", "");
		byte[] bytes = new byte[value.length() / 2];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
		}
		return bytes;
	}

	static String toString(byte[] bytes) {
		StringBuilder sb = new StringBuilder(bytes.length * 2);
		for (byte b : bytes) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

}
