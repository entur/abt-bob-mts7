package no.entur.abt.bob.mts7.core.pki;

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

}
