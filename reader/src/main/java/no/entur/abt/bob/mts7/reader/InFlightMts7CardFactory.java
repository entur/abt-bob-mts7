package no.entur.abt.bob.mts7.reader;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Random;

import no.entur.abt.bob.mts7.api.Mts7Exception;
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

	public InFlightMts7Card create(Mts7Exchange mts7Exchange, byte[] selectApplicationResponse) throws IOException, Mts7Exception, InterruptedException {
		Mts7Processor processor = processorFactory.create();
		processor.start();

		Mts7ApduExchanges online = mts7CardInvocationsFactory.create(mts7Exchange, processor, selectApplicationResponse);

		InFlightMts7Card result = new InFlightMts7Card();
		result.setMts7ApduExchanges(online);
		result.setProcessor(processor);

		return result;
	}
}
