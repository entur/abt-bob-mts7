package no.entur.abt.bob.mts7.reader.processor;

import java.util.concurrent.ExecutionException;

import no.entur.abt.bob.mts7.api.apdu.CommandAPDU;
import no.entur.abt.bob.mts7.core.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.Mts7Card;

public interface Mts7Processor extends Runnable {

	void start();

	void close();

	/**
	 * Wait for the algorithm of the signatures of the card to be known, from the type of its public key (not from <code>alg</code> in the header, which is the
	 * algorithm of the issuer signature).
	 *
	 * @param delay time to wait in milliseconds, or zero to wait until the algorithm is known or the processor is closed or has finished
	 * @return ES256 for an EC key, RS256 for an RSA key, or null if it is not known (yet)
	 * @throws InterruptedException if interrupted while waiting
	 */

	String waitForAlgorithm(long delay) throws InterruptedException;

	/**
	 * Wait for the card to be processed, and return it if it was verified.
	 *
	 * @param timeout time to wait in milliseconds, or zero to wait until the processing is finished
	 * @return the verified card
	 * @throws InterruptedException     if interrupted while waiting
	 * @throws InvalidCardMts7Exception if the card is not valid, could not be verified, or was not completely read (a problem on the card side). See the
	 *                                  subclasses {@linkplain no.entur.abt.bob.mts7.core.KeyPairInvalidCardMts7Exception} and
	 *                                  {@linkplain no.entur.abt.bob.mts7.core.TrustChainInvalidCardMts7Exception}.
	 * @throws ExecutionException       if the processing failed because of a problem on our side, which is the cause
	 */

	Mts7Card waitForVerify(long timeout) throws InterruptedException, InvalidCardMts7Exception, ExecutionException;

	void onGetData(byte[] responsePayload);

	void onInternalAuthenticate(byte[] commandPayload, byte[] responsePayload);

	void onSelectApplication(byte[] responsePayload);

	// for testing
	default void onGetDataResponseApdu(byte[] response) {
		byte[] payload = new byte[response.length - 2];
		System.arraycopy(response, 0, payload, 0, payload.length);
		onGetData(payload);
	}

	default void onInternalAuthenticateApdu(byte[] commandPayload, byte[] responseApdu) {
		CommandAPDU apdu = new CommandAPDU(commandPayload);

		byte[] payload = new byte[responseApdu.length - 2];
		System.arraycopy(responseApdu, 0, payload, 0, payload.length);

		onInternalAuthenticate(apdu.getData(), payload);
	}

	default void onSelectApplicationResponseApdu(byte[] response) {
		byte[] payload = new byte[response.length - 2];
		System.arraycopy(response, 0, payload, 0, payload.length);
		onSelectApplication(payload);
	}

}
