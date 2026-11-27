package no.entur.abt.bob.mts7.reader;

import java.io.IOException;
import java.util.Arrays;
import java.util.Random;

import no.entur.abt.bob.mts7.api.Mts7Exception;
import no.entur.abt.bob.mts7.reader.processor.Mts7Processor;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchanges;
import no.entur.abt.bob.mts7.simple.reader.DefaultMts7Exchange;
import no.entur.abt.bob.mts7.simple.reader.Mts7ApduExchangesFactory;
import no.entur.abt.bob.mts7.simple.reader.Mts7Exchange;

/**
 * 
 * Card factory which does minimal work to gather the card data while also feeding an underlying processor.
 * <p>
 * Instances are thread safe (given that the random is), so a single instance can be shared by all card readers.
 *
 */

public class ProcessorMts7ApduExchangesFactory extends Mts7ApduExchangesFactory {

	public ProcessorMts7ApduExchangesFactory() {
		super();
	}

	public ProcessorMts7ApduExchangesFactory(Random random) {
		super(random);
	}

	public Mts7ApduExchanges create(Mts7Exchange mts7Exchange, Mts7Processor processor, byte[] selectApplicationResponse)
			throws IOException, Mts7Exception, InterruptedException {
		DefaultMts7Exchange result = new DefaultMts7Exchange(mts7Exchange);

		// go via the recording exchange so that the commands and responses end up in the result
		handleSelectApplication(result, processor, selectApplicationResponse);

		handleGetNextData(result, processor);

		handleInternalAuthenticate(result, processor);

		return result;
	}

	protected void handleSelectApplication(DefaultMts7Exchange mts7Exchange, Mts7Processor processor, byte[] selectApplicationResponse)
			throws IOException, Mts7Exception {
		byte[] response = handleSelectApplication(selectApplicationResponse, mts7Exchange);
		processor.onSelectApplicationResponseApdu(response);

		if (!hasApplicationRelatedData(response)) {
			// the card need not return it in the select application response (MTS7 section 4.1.1)
			processor.onApplicationRelatedDataResponseApdu(handleGetApplicationRelatedData(mts7Exchange));
		}
	}

	protected void handleInternalAuthenticate(Mts7Exchange mts7Exchange, Mts7Processor processor) throws IOException, Mts7Exception {
		// random bytes, i.e. same as SHA-256
		byte[] command = createInternalAuthenticateCommand();
		byte[] response = handleInternalAuthenticate(mts7Exchange, command);

		byte[] challenge = Arrays.copyOfRange(command, INTERNAL_AUTHENTICATE_COMMAND_PREFIX.length,
				command.length - INTERNAL_AUTHENTICATE_COMMAND_POSTFIX.length);

		processor.onInternalAuthenticate(challenge, Arrays.copyOf(response, response.length - 2));
	}

	protected void handleGetNextData(Mts7Exchange mts7Exchange, Mts7Processor processor) throws IOException, Mts7Exception {
		byte[] response = handleGetNextData(mts7Exchange);

		processor.onGetData(Arrays.copyOf(response, response.length - 2));
	}

}
