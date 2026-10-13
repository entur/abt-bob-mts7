package no.entur.abt.bob.mts7.core.pki;

import java.security.Signature;
import java.security.SignatureException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.ECDSA;

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
			byte[] encoded = encode(sign);

			signature.update(data);
			return signature.verify(encoded);
		} catch (Exception e) {
			return false;
		}
	}

	public boolean verify(byte[] data, int offset, int length, byte[] sign) throws SignatureException {
		try {
			byte[] encoded = encode(sign);

			signature.update(data, offset, length);
			return signature.verify(encoded);
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * The signature of an EC key is the two vectors r and s concatenated (as in JWS), but java expects DER.
	 */

	private byte[] encode(byte[] sign) throws JOSEException {
		if (signature.getAlgorithm().endsWith("ECDSA")) {
			return ECDSA.transcodeSignatureToDER(sign);
		}
		return sign;
	}

	public long getPid() {
		return pid;
	}

	public String getKid() {
		return kid;
	}
}
