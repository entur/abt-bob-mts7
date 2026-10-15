package no.entur.abt.bob.mts7.core.mtb;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Token Public Key (tpk) of the Issuer Signature Protected Header, a JWK (RFC 7517) with the public key of the card.
 */

@JsonIgnoreProperties(ignoreUnknown = true)
public class TokenPublicKey {

	private String kty;

	// rsa
	private String n;
	private String e;

	// ec
	private String crv;
	private String x;
	private String y;

	public String getKty() {
		return kty;
	}

	public void setKty(String kty) {
		this.kty = kty;
	}

	public String getN() {
		return n;
	}

	public void setN(String n) {
		this.n = n;
	}

	public String getE() {
		return e;
	}

	public void setE(String e) {
		this.e = e;
	}

	public String getCrv() {
		return crv;
	}

	public void setCrv(String crv) {
		this.crv = crv;
	}

	public String getX() {
		return x;
	}

	public void setX(String x) {
		this.x = x;
	}

	public String getY() {
		return y;
	}

	public void setY(String y) {
		this.y = y;
	}

}
