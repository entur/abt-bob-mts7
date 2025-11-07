package no.entur.abt.bob.mts7.core.pki;

import java.io.ByteArrayOutputStream;
import java.security.SignatureException;
import java.util.Map;

import no.entur.abt.bob.mts7.core.UnableToConstructIccKeyException;

public class IccPublicKeyBuilder {

	protected final IccPublicKeyFactory iccSignatureFactory;

	protected ByteArrayOutputStream payload = new ByteArrayOutputStream();

	protected IssuerPublicKey issuerPublicKey;

	protected byte[] signature;

	protected Map<String, Object> issuerSignatureProtectedHeader;

	public IccPublicKeyBuilder(IccPublicKeyFactory factory) {
		this.iccSignatureFactory = factory;
	}

	public boolean canBuild() {
		if (payload.size() == 0) {
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

	public IccPublicKeyBuilder withSignedData(byte[] buffer, int offset, int length) {
		payload.write(buffer, offset, length);
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
		payload.reset();

		signature = null;
		issuerPublicKey = null;
	}

	public IccPublicKey build() throws SignatureException, UnableToConstructIccKeyException {
		byte[] data = payload.toByteArray();

		issuerPublicKey.verify(data, signature);

		return iccSignatureFactory.create(issuerSignatureProtectedHeader);
	}

}
