package no.entur.abt.bob.mts7.reader.processor;

import java.security.NoSuchAlgorithmException;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.core.Mts7CardEnricher;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;

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
