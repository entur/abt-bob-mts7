package no.entur.abt.bob.mts7.reader.processor;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Objects;
import java.util.concurrent.Executor;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.core.Mts7CardEnricher;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;

/**
 * Factory for processors which verify that the card has the private key (not the key chain).
 *
 * <p>
 * This class is thread safe: the helpers which the processors share are thread safe, and each processor is used for one card only. So a single instance should
 * be shared by all card readers (and threads), which is also the cheapest way to use it.
 *
 * <p>
 * The processors run on the threads of an executor. A processor waits for the card reader to give it input, so the executor must be able to run all of the
 * processors which exist at the same time (a bounded pool with fewer threads than that will make them wait for each other), and must not run them on the
 * thread which reads the card (that thread would wait for itself). The executor belongs to the application, which shuts it down when it is no longer needed;
 * the factory neither creates nor shuts down any executors.
 */

public class VerifyKeyPairMts7ProcessorFactory implements Mts7ProcessorFactory {

	protected final IccPublicKeyFactory factory;

	protected final Mts7CardEnricher enricher;
	protected final CBORMapper cborMapper;
	protected final ThumbprintFactory thumbprintFactory;
	protected final Executor executor;

	/**
	 * Constructor.
	 *
	 * @param executor executor for the processors, which belongs to the caller
	 * @throws NoSuchAlgorithmException if the digest algorithm is not available
	 */

	public VerifyKeyPairMts7ProcessorFactory(Executor executor) throws NoSuchAlgorithmException {
		this(null, executor);
	}

	/**
	 * Constructor.
	 *
	 * @param provider security provider (for signatures and digests), or null for the default
	 * @param executor executor for the processors
	 * @throws NoSuchAlgorithmException if the digest algorithm is not available
	 */

	public VerifyKeyPairMts7ProcessorFactory(Provider provider, Executor executor) throws NoSuchAlgorithmException {
		this(new IccPublicKeyFactory(provider), new Mts7CardEnricher(), new CBORMapper(), new ThumbprintFactory(provider), executor);
	}

	/**
	 * Constructor for sharing the helpers with other factories. All of the helpers must be thread safe.
	 *
	 * @param factory           factory for the public key of the card
	 * @param enricher          card enricher
	 * @param cborMapper        CBOR mapper
	 * @param thumbprintFactory thumbprint factory
	 * @param executor          executor for the processors
	 */

	public VerifyKeyPairMts7ProcessorFactory(IccPublicKeyFactory factory, Mts7CardEnricher enricher, CBORMapper cborMapper, ThumbprintFactory thumbprintFactory,
			Executor executor) {
		this.factory = factory;
		this.enricher = enricher;
		this.cborMapper = cborMapper;
		this.thumbprintFactory = thumbprintFactory;
		// fail now rather than for the first card
		this.executor = Objects.requireNonNull(executor, "executor");
	}

	public VerifyKeyPairMts7Processor create() {
		return new VerifyKeyPairMts7Processor(factory, enricher, cborMapper, thumbprintFactory, executor);
	}

}
