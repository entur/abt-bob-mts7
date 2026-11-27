package no.entur.abt.bob.mts7.reader.processor;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.api.ReaderMts7Exception;
import no.entur.abt.bob.mts7.api.apdu.CommandAPDU;
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
	 * @throws ReaderMts7Exception      if the input is not as a reader following MTS7 provides it, or the card was not completely read (a problem with the
	 *                                  reader)
	 * @throws TimeoutException         if the processing did not finish within the timeout
	 * @throws InvalidCardMts7Exception if the card is not valid, could not be verified, (a problem on the card side). See the subclasses
	 *                                  {@linkplain no.entur.abt.bob.mts7.core.exception.KeyPairInvalidCardMts7Exception} and
	 *                                  {@linkplain no.entur.abt.bob.mts7.core.exception.TrustChainInvalidCardMts7Exception}.
	 * @throws ExecutionException       if the processing failed because of a problem with the verifier, which is the cause
	 */

	Mts7Card waitForVerify(long timeout) throws InterruptedException, InvalidCardMts7Exception, ReaderMts7Exception, TimeoutException, ExecutionException;

	void onGetData(byte[] responsePayload);

	/**
	 * The response to GET DATA of the application-related data (6E), which the reader sends, before GET (NEXT) DATA of the MTB, if the select application
	 * response does not have it (MTS7 section 4.1.1).
	 *
	 * @param responsePayload the response payload, without the status word
	 */

	void onApplicationRelatedData(byte[] responsePayload);

	/**
	 * The command and the response of internal authenticate.
	 *
	 * @param commandPayload  the data of the command, i.e. the challenge (not the command APDU)
	 * @param responsePayload the response payload, i.e. the signature, without the status word
	 */

	void onInternalAuthenticate(byte[] commandPayload, byte[] responsePayload);

	void onSelectApplication(byte[] responsePayload);

	// for testing
	default void onGetDataResponseApdu(byte[] response) {
		byte[] payload = new byte[response.length - 2];
		System.arraycopy(response, 0, payload, 0, payload.length);
		onGetData(payload);
	}

	default void onInternalAuthenticateApdu(byte[] commandApdu, byte[] responseApdu) {
		CommandAPDU apdu = new CommandAPDU(commandApdu);

		byte[] payload = new byte[responseApdu.length - 2];
		System.arraycopy(responseApdu, 0, payload, 0, payload.length);

		onInternalAuthenticate(apdu.getData(), payload);
	}

	default void onApplicationRelatedDataResponseApdu(byte[] response) {
		byte[] payload = new byte[response.length - 2];
		System.arraycopy(response, 0, payload, 0, payload.length);
		onApplicationRelatedData(payload);
	}

	default void onSelectApplicationResponseApdu(byte[] response) {
		byte[] payload = new byte[response.length - 2];
		System.arraycopy(response, 0, payload, 0, payload.length);
		onSelectApplication(payload);
	}

}
