package no.entur.abt.bob.mts7.core.mtb;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The Issuer Signature Protected Header, which provides the metadata for the issuer signature of the ticket bundle.
 *
 * <pre>
 * The Issuer Signature Protected Header SHALL include the following parameters:
 * • alg – Signature Algorithm (string)
 * • iid – Issuer Identifier (string)
 * • kid – Key identifier (string)
 * • miv – Mobile Ticket Specification minor version number (number)
 *
 * To be able to distinguish between the Issuer Signature and the Device Signature (see section 2.5)
 * header, the Issuer Signature Protected Header MUST NOT contain a did parameter.
 *
 * The Issuer Signature Protected Header MAY include the following parameters:
 * • exp – Signature Expiry (timestamp in ISO 8601:2004 profile basic format, see 2.2 in (MTS8), string)
 * • nbf – Signature Inception (timestamp in ISO 8601:2004 profile basic format, see 2.2 in (MTS8), string)
 * • dsp – Device Signature Provider (string)
 * • dsi – Device Signature Identifier (string)
 * • tpk – Token Public Key (object)
 * </pre>
 */

@JsonIgnoreProperties(ignoreUnknown = true)
public class IssuerSignatureProtectedHeader {

	private String alg;
	private String iid;
	private String kid;
	private int miv;

	private String exp;
	private String nbf;
	private String dsp;
	private String dsi;

	private TokenPublicKey tpk;

	// only present in the Device Signature Protected Header
	private String did;

	public String getAlg() {
		return alg;
	}

	public void setAlg(String alg) {
		this.alg = alg;
	}

	public String getIid() {
		return iid;
	}

	public void setIid(String iid) {
		this.iid = iid;
	}

	public String getKid() {
		return kid;
	}

	public void setKid(String kid) {
		this.kid = kid;
	}

	public int getMiv() {
		return miv;
	}

	public void setMiv(int miv) {
		this.miv = miv;
	}

	public String getExp() {
		return exp;
	}

	public void setExp(String exp) {
		this.exp = exp;
	}

	public String getNbf() {
		return nbf;
	}

	public void setNbf(String nbf) {
		this.nbf = nbf;
	}

	public String getDsp() {
		return dsp;
	}

	public void setDsp(String dsp) {
		this.dsp = dsp;
	}

	public String getDsi() {
		return dsi;
	}

	public void setDsi(String dsi) {
		this.dsi = dsi;
	}

	public TokenPublicKey getTpk() {
		return tpk;
	}

	public void setTpk(TokenPublicKey tpk) {
		this.tpk = tpk;
	}

	public String getDid() {
		return did;
	}

	public void setDid(String did) {
		this.did = did;
	}

	/**
	 * @return true if this is a Device Signature Protected Header, i.e. not an Issuer Signature Protected Header
	 */

	@JsonIgnore
	public boolean isDeviceSignatureProtectedHeader() {
		return did != null;
	}

}
