package no.entur.abt.bob.mts7.core.exception;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import no.entur.abt.bob.mts7.api.VerifierMts7Exception;

/**
 * An algorithm is not available from the security provider (a problem with the verifier). The cause is the {@linkplain NoSuchAlgorithmException}.
 */

public class NoSuchAlgorithmMts7Exception extends VerifierMts7Exception {

	private static final long serialVersionUID = 1L;

	private final String algorithm;

	/**
	 * Constructor.
	 *
	 * @param algorithm the algorithm, as in {@linkplain java.security.Signature#getInstance(String)}
	 * @param provider  the security provider, or null for the default
	 * @param cause     the exception from the security provider
	 */

	public NoSuchAlgorithmMts7Exception(String algorithm, Provider provider, NoSuchAlgorithmException cause) {
		super("Algorithm " + algorithm + " is not available from "
				+ (provider != null ? "security provider " + provider.getName() : "the default security providers"), cause);
		this.algorithm = algorithm;
	}

	/**
	 * @return the algorithm which is not available
	 */

	public String getAlgorithm() {
		return algorithm;
	}

}
