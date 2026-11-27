package no.entur.abt.bob.mts7.reader;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.api.Mts7Exception;
import no.entur.abt.bob.mts7.api.ReaderMts7Exception;
import no.entur.abt.bob.mts7.reader.processor.Mts7Processor;
import no.entur.abt.bob.mts7.reader.processor.Mts7ProcessorFactory;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchanges;
import no.entur.abt.bob.mts7.simple.reader.Mts7Exchange;

/**
 * 
 * Read card and return binary card without parsing content.
 *
 */

public class InFlightMts7CardFactory {

	protected final ProcessorMts7ApduExchangesFactory mts7CardInvocationsFactory;
	protected final Mts7ProcessorFactory processorFactory;

	public InFlightMts7CardFactory(Mts7ProcessorFactory processorFactory) throws Exception {
		this(processorFactory, new SecureRandom());
	}

	public InFlightMts7CardFactory(Mts7ProcessorFactory processorFactory, Random random) throws Exception {
		this.processorFactory = processorFactory;

		this.mts7CardInvocationsFactory = new ProcessorMts7ApduExchangesFactory(random);
	}

	/**
	 * The verdict of the processor on what has been read of the card, if it finds that the card is not valid.
	 *
	 * @param processor the processor, which is closed, so that it does not wait for more input
	 * @return the problem on the card side, or null if none was found
	 * @throws InterruptedException if interrupted while waiting for the processor
	 */

	protected static InvalidCardMts7Exception getInvalidCard(Mts7Processor processor) throws InterruptedException {
		processor.close();
		try {
			// once closed, the processing finishes promptly: it does not wait for more input
			processor.waitForVerify(0);
		} catch (InvalidCardMts7Exception e) {
			return e;
		} catch (ReaderMts7Exception | TimeoutException | ExecutionException | RuntimeException e) {
			// not the fault of the card, as far as it was read
		}
		return null;
	}

	public InFlightMts7Card create(Mts7Exchange mts7Exchange, byte[] selectApplicationResponse) throws IOException, Mts7Exception, InterruptedException {
		Mts7Processor processor = processorFactory.create();
		processor.start();

		boolean success = false;
		try {
			Mts7ApduExchanges online = mts7CardInvocationsFactory.create(mts7Exchange, processor, selectApplicationResponse);

			InFlightMts7Card result = new InFlightMts7Card();
			result.setMts7ApduExchanges(online);
			result.setProcessor(processor);

			success = true;

			return result;
		} catch (IOException | ReaderMts7Exception e) {
			// The card was not completely read, but what was read of it may already show that it is not valid, so that the card is to blame for that, also
			// when it stops responding, or makes the reader fail, after its MTB.
			InvalidCardMts7Exception invalid = getInvalidCard(processor);
			if (invalid != null) {
				invalid.addSuppressed(e);
				throw invalid;
			}
			throw e;
		} finally {
			if (!success) {
				// the caller does not get a card to close, so stop the processor (which is waiting for input from the card) here
				processor.close();
			}
		}
	}
}
