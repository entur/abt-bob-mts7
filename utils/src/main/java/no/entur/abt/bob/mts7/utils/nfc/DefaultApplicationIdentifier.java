package no.entur.abt.bob.mts7.utils.nfc;

import java.util.Arrays;

public class DefaultApplicationIdentifier implements ApplicationIdentifier {

	private final byte[] aid;

	public DefaultApplicationIdentifier(byte[] aid) {
		this.aid = aid;
	}

	public DefaultApplicationIdentifier(byte[] bytes, int offset, int length) {
		byte[] aid = new byte[length];
		for (int i = 0; i < aid.length; i++) {
			aid[i] = (byte) bytes[offset + i];
		}
		this.aid = aid;
	}

	public DefaultApplicationIdentifier(int... aidBytes) {
		byte[] aid = new byte[aidBytes.length];
		for (int i = 0; i < aid.length; i++) {
			aid[i] = (byte) aidBytes[i];
		}
		this.aid = aid;
	}

	@Override
	public byte[] getBytes() {
		return aid;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		for (byte b : aid) {
			sb.append(String.format("%02X ", b));
		}
		return sb.toString().trim();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(aid);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		DefaultApplicationIdentifier other = (DefaultApplicationIdentifier) obj;
		return Arrays.equals(aid, other.aid);
	}

}
