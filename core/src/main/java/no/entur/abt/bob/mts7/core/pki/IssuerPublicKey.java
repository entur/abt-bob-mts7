package no.entur.abt.bob.mts7.core.pki;

import java.security.Signature;
import java.security.SignatureException;

public class IssuerPublicKey {

	private final long pid;
	private final String kid;

	protected Signature signature;

	public IssuerPublicKey(long pid, String kid, Signature signature) {
		this.pid = pid;
		this.kid = kid;
		this.signature = signature;
	}

	public boolean verify(byte[] data, byte[] sign) throws SignatureException {
		try {
			signature.update(data);
			return signature.verify(sign);
		} catch (Exception e) {
			return false;
		}
	}

	public boolean verify(byte[] data, int offset, int length, byte[] sign) throws SignatureException {
		try {
			signature.update(data, offset, length);
			return signature.verify(sign);
		} catch (Exception e) {
			return false;
		}
	}

	public long getPid() {
		return pid;
	}

	public String getKid() {
		return kid;
	}
}
