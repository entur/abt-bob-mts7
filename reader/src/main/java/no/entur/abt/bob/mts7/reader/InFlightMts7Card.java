package no.entur.abt.bob.mts7.reader;

import java.io.Closeable;
import java.util.concurrent.ExecutionException;

import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.reader.processor.Mts7Processor;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchanges;

/**
 * 
 * Card which supports an "online with offline option" approach.
 * 
 */

public class InFlightMts7Card implements Closeable {

	private Mts7ApduExchanges mts7ApduExchanges;
	private Mts7Processor processor;

	public void setMts7ApduExchanges(Mts7ApduExchanges mts7CardInvocations) {
		this.mts7ApduExchanges = mts7CardInvocations;
	}

	public void setProcessor(Mts7Processor processor) {
		this.processor = processor;
	}

	public Mts7ApduExchanges getMts7ApduExchanges() {
		return mts7ApduExchanges;
	}

	/**
	 * Get the card, as verified while it was read.
	 *
	 * @param timeout time to wait in milliseconds, or zero to wait until the processing is finished
	 * @return the verified card
	 * @throws InterruptedException     if interrupted while waiting
	 * @throws InvalidCardMts7Exception if the card is not valid, could not be verified, or was not completely read (a problem on the card side)
	 * @throws ExecutionException       if the processing failed because of a problem on our side, which is the cause
	 */

	public Mts7Card getMts7Card(long timeout) throws InterruptedException, InvalidCardMts7Exception, ExecutionException {
		return processor.waitForVerify(timeout);
	}

	@Override
	public void close() {
		processor.close();
	}

}
