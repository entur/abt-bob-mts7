package no.entur.abt.bob.mts7.reader.processor;

import java.security.NoSuchAlgorithmException;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.core.Mts7CardEnricher;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;

public class VerifyTrustChainMts7ProcessorFactory implements Mts7ProcessorFactory {

	protected final ParticipantPublicKeys participantPublicKeys;
	protected final IccPublicKeyFactory factory = new IccPublicKeyFactory();

	protected final Mts7CardEnricher enricher = new Mts7CardEnricher();
	protected final CBORMapper cborMapper = new CBORMapper();
	protected final ThumbprintFactory thumbprintFactory;

	public VerifyTrustChainMts7ProcessorFactory(ParticipantPublicKeys participantPublicKeys) throws NoSuchAlgorithmException {
		this.participantPublicKeys = participantPublicKeys;
		this.thumbprintFactory = new ThumbprintFactory(null);
	}

	public VerifyTrustChainMts7Processor create() {
		return new VerifyTrustChainMts7Processor(participantPublicKeys, factory, enricher, cborMapper, thumbprintFactory);
	}

}
