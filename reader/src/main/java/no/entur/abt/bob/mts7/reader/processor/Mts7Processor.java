package no.entur.abt.bob.mts7.reader.processor;

import no.entur.abt.bob.mts7.api.apdu.CommandAPDU;
import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.core.UnableToVerifyKeyPairException;
import no.entur.abt.bob.mts7.core.UnableToVerifyTrustChainException;

public interface Mts7Processor extends Runnable {

	void start();

	void close();

	String waitForAlgorithm(long delay) throws InterruptedException;

	Mts7Card waitForVerify(long timeout) throws InterruptedException, UnableToVerifyKeyPairException, UnableToVerifyTrustChainException;

	void onGetData(byte[] responsePayload);

	void onInternalAuthenticate(byte[] commandPayload, byte[] responsePayload);

	void onSelectApplication(byte[] responsePayload);

	// for testing
	default void onGetDataResponseApdu(byte[] response) {
		byte[] payload = new byte[response.length - 2];
		System.arraycopy(response, 0, payload, 0, payload.length);
		onGetData(response);
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
		onSelectApplication(response);
	}

}
