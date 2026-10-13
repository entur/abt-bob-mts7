package no.entur.abt.bob.mts7.reader.processor;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.concurrent.Executor;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.core.Mts7CardEnricher;
import no.entur.abt.bob.mts7.core.Mts7Warmup;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;

/**
 * Factory for processors which verify that the card has the private key, and the key chain.
 *
 * <p>
 * This class is thread safe: the helpers which the processors share (including the {@linkplain ParticipantPublicKeys}) are thread safe, and each processor is
 * used for one card only. So a single instance should be shared by all card readers (and threads), which is also the cheapest way to use it.
 *
 * <p>
 * The processors run on the threads of an executor. A processor waits for the card reader to give it input, so the executor must be able to run all of the
 * processors which exist at the same time (a bounded pool with fewer threads than that will make them wait for each other), and must not run them on the
 * thread which reads the card (that thread would wait for itself). By default each processor gets a new daemon thread (see
 * {@linkplain AbstractMts7Processor#NEW_DAEMON_THREAD}); pass an executor to reuse threads for the next card, for example one from
 * {@linkplain AbstractMts7Processor#newThreadPool()}. The factory does not create or shut down any executors.
 */

public class VerifyTrustChainMts7ProcessorFactory implements Mts7ProcessorFactory {

	protected final ParticipantPublicKeys participantPublicKeys;
	protected final IccPublicKeyFactory factory;

	protected final Mts7CardEnricher enricher;
	protected final CBORMapper cborMapper;
	protected final ThumbprintFactory thumbprintFactory;
	protected final Executor executor;

	public VerifyTrustChainMts7ProcessorFactory(ParticipantPublicKeys participantPublicKeys) throws NoSuchAlgorithmException {
		this(participantPublicKeys, (Provider) null);
	}

	/**
	 * Constructor.
	 *
	 * @param participantPublicKeys issuer keys, shared with other factories and threads
	 * @param provider              security provider (for signatures and digests), or null for the default
	 * @throws NoSuchAlgorithmException if the digest algorithm is not available
	 */

	public VerifyTrustChainMts7ProcessorFactory(ParticipantPublicKeys participantPublicKeys, Provider provider) throws NoSuchAlgorithmException {
		this(participantPublicKeys, provider, AbstractMts7Processor.NEW_DAEMON_THREAD);
	}

	/**
	 * Constructor.
	 *
	 * @param participantPublicKeys issuer keys, shared with other factories and threads
	 * @param executor              executor for the processors
	 * @throws NoSuchAlgorithmException if the digest algorithm is not available
	 */

	public VerifyTrustChainMts7ProcessorFactory(ParticipantPublicKeys participantPublicKeys, Executor executor) throws NoSuchAlgorithmException {
		this(participantPublicKeys, null, executor);
	}

	/**
	 * Constructor.
	 *
	 * @param participantPublicKeys issuer keys, shared with other factories and threads
	 * @param provider              security provider (for signatures and digests), or null for the default
	 * @param executor              executor for the processors
	 * @throws NoSuchAlgorithmException if the digest algorithm is not available
	 */

	public VerifyTrustChainMts7ProcessorFactory(ParticipantPublicKeys participantPublicKeys, Provider provider, Executor executor)
			throws NoSuchAlgorithmException {
		this(participantPublicKeys, new IccPublicKeyFactory(provider), new Mts7CardEnricher(), new CBORMapper(), new ThumbprintFactory(provider), executor);
	}

	/**
	 * Constructor for sharing the helpers with other factories. All of the helpers must be thread safe.
	 *
	 * @param participantPublicKeys issuer keys, shared with other factories and threads
	 * @param factory               factory for the public key of the card
	 * @param enricher              card enricher
	 * @param cborMapper            CBOR mapper
	 * @param thumbprintFactory     thumbprint factory
	 * @param executor              executor for the processors
	 */

	public VerifyTrustChainMts7ProcessorFactory(ParticipantPublicKeys participantPublicKeys, IccPublicKeyFactory factory, Mts7CardEnricher enricher,
			CBORMapper cborMapper, ThumbprintFactory thumbprintFactory, Executor executor) {
		this.participantPublicKeys = participantPublicKeys;
		this.factory = factory;
		this.enricher = enricher;
		this.cborMapper = cborMapper;
		this.thumbprintFactory = thumbprintFactory;
		this.executor = executor;
	}

	public VerifyTrustChainMts7Processor create() {
		return new VerifyTrustChainMts7Processor(participantPublicKeys, factory, enricher, cborMapper, thumbprintFactory, executor);
	}

	/**
	 * Do the work which otherwise is done for the first card, so call this when the application starts (for example on a background thread). Never throws.
	 */

	public void warmUp() {
		Mts7Warmup.warmUp(cborMapper, enricher, factory);
	}

}
