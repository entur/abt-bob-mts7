package no.entur.abt.bob.mts7.core;

import no.entur.abt.bob.mts7.api.Mts7Exception;

public class UnableToVerifyKeyPairException extends Mts7Exception {

	private static final long serialVersionUID = 1L;

	private final Mts7Card result;

	public UnableToVerifyKeyPairException(Mts7Card result) {
		super("Unable to verify that private key is present for MTS7 card");
		this.result = result;
	}

	public Mts7Card getResult() {
		return result;
	}

}
