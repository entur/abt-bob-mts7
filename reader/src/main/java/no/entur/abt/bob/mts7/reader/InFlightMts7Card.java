package no.entur.abt.bob.mts7.reader;

import java.io.Closeable;

import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.core.UnableToVerifyKeyPairException;
import no.entur.abt.bob.mts7.core.UnableToVerifyTrustChainException;
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

	public Mts7Card getMts7Card(long timeout) throws InterruptedException, UnableToVerifyKeyPairException, UnableToVerifyTrustChainException {
		return processor.waitForVerify(timeout);
	}

	@Override
	public void close() {
		processor.close();
	}

}
