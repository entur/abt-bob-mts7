package no.entur.abt.bob.mts7.reader.processor;

import java.security.NoSuchAlgorithmException;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.core.Mts7CardEnricher;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;

/**
 * Factory for processors which verify that the card has the private key (not the key chain).
 *
 * <p>
 * This class is not thread safe. The processors share (non thread safe) helper instances with the factory and with each other, so processors created by the
 * same factory instance must not run at the same time. Use a separate factory instance per thread, or per card being read.
 */

public class VerifyKeyPairMts7ProcessorFactory implements Mts7ProcessorFactory {

	protected final IccPublicKeyFactory factory = new IccPublicKeyFactory();

	protected final Mts7CardEnricher enricher = new Mts7CardEnricher();
	protected final CBORMapper cborMapper = new CBORMapper();
	protected final ThumbprintFactory thumbprintFactory;

	public VerifyKeyPairMts7ProcessorFactory() throws NoSuchAlgorithmException {
		this.thumbprintFactory = new ThumbprintFactory(null);
	}

	public VerifyKeyPairMts7Processor create() {
		return new VerifyKeyPairMts7Processor(factory, enricher, cborMapper, thumbprintFactory);
	}

}
