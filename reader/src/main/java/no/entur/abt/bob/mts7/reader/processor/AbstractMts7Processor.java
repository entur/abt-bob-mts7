package no.entur.abt.bob.mts7.reader.processor;

import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.BooleanSupplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import no.entur.abt.bob.mts7.api.InsufficientCardCommandsException;
import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.api.ReaderMts7Exception;
import no.entur.abt.bob.mts7.core.MalformedCardCommandException;
import no.entur.abt.bob.mts7.core.MissingCardCommandsException;
import no.entur.abt.bob.mts7.core.Mts7ApduPayloadsFactory;
import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.core.Mts7CardEnricher;

/**
 * Base class for processors: the part which is about running alongside the card reader, i.e. receiving what the reader gets from the card on one thread, and
 * processing it on another.
 *
 * <p>
 * A processor is for a single card, so it must not be reused. The methods which receive the input from the card, {@linkplain #close()} and the methods which
 * wait for the result can be called from any thread, any number of times. The processing itself is done by {@linkplain #run()} (which is called by the executor
 * when the processor is started), and reads the input in the order in which it is needed, so the card reader can give the processor its input as soon as it has
 * it.
 *
 * <p>
 * The processing waits for input from the card, so it needs a thread to itself while it does: an executor which cannot run all of the processors which are
 * started at the same time (a bounded pool, or one which runs the task on the calling thread) will make them wait for each other.
 *
 * <p>
 * The executor is always provided by the application, which owns it and so is the one to shut it down; nothing in this library creates an executor or a thread
 * of its own. As a processor stops waiting for the card after {@linkplain #DEFAULT_MAX_LIFETIME_MILLIS}, its thread is never blocked for much longer than that,
 * but the threads of the executor are not daemon threads unless the application makes them so.
 *
 * <p>
 * The processing reports a problem on the card side by throwing an {@linkplain InvalidCardMts7Exception} (or a subclass) from {@linkplain #process()}, which
 * {@linkplain #waitForVerify(long)} then throws as it is, and so with a problem with the reader ({@linkplain ReaderMts7Exception}). A problem with the verifier
 * is an {@linkplain no.entur.abt.bob.mts7.api.VerifierMts7Exception} (or a subclass), which {@linkplain #waitForVerify(long)} throws as the cause of an
 * {@linkplain ExecutionException}, as it does anything else, such as a {@linkplain java.util.concurrent.RejectedExecutionException} if the executor did not run
 * the processor, or a {@linkplain RuntimeException}, which is a bug.
 */

public abstract class AbstractMts7Processor implements Mts7Processor {

	/**
	 * For how long the processing waits for the input from the card, counted from when it starts. The card has to be read within this time, no matter whether
	 * somebody ever closes the processor, so that it cannot be left waiting for input which never arrives.
	 */

	public static final long DEFAULT_MAX_LIFETIME_MILLIS = 60 * 1000;

	// log as the processor which is running
	private final Logger logger = LoggerFactory.getLogger(getClass());

	protected volatile boolean close;

	protected final Object inputMonitor = new Object();
	protected final Object outputMonitor = new Object();

	// written under the input monitor, and volatile so that they can be read without it afterwards
	protected volatile byte[] selectApplicationResponsePayload;
	protected volatile byte[] getDataResponsePayload;
	protected volatile byte[] applicationRelatedDataPayload;

	/**
	 * The command and the response of one call of {@linkplain #onInternalAuthenticate(byte[], byte[])}. They are kept together, so that the command of one call
	 * is never verified against the response of another.
	 */

	static final class InternalAuthenticate {

		final byte[] command;
		final byte[] response;

		InternalAuthenticate(byte[] command, byte[] response) {
			this.command = command;
			this.response = response;
		}
	}

	volatile InternalAuthenticate internalAuthenticate;

	// never null, so that waitForVerify(..) can report on a processor which did not get any input. Only modify it using updateResult(..)
	protected final Mts7Card result = new Mts7Card();
	private final Object resultLock = new Object();

	protected volatile String iccKeyAlgorithm;

	private final Executor executor;

	// guarded by the input monitor
	private boolean started;

	// whether the processing has begun to run, after which it finishes promptly once closed
	private volatile boolean ran;

	// why the input stopped before the card was completely read, if it did
	private volatile String incompleteReason;

	// guarded by the output monitor
	private boolean processed;

	// when the processing is done (successfully or not), also if it never was started
	private final CountDownLatch finished = new CountDownLatch(1);

	private volatile long deadline;

	// why the processing failed, or null if it did not (yet). Set before the processing is finished
	private volatile Exception failure;

	/**
	 * Constructor.
	 *
	 * @param executor executor for running the processing. It belongs to the caller, who must shut it down when it is no longer needed; the processor does not
	 */

	protected AbstractMts7Processor(Executor executor) {
		this.executor = Objects.requireNonNull(executor, "executor");
	}

	@Override
	public void onGetData(byte[] responsePayload) {
		synchronized (inputMonitor) {
			this.getDataResponsePayload = responsePayload;

			inputMonitor.notifyAll();
		}
	}

	@Override
	public void onApplicationRelatedData(byte[] responsePayload) {
		synchronized (inputMonitor) {
			this.applicationRelatedDataPayload = responsePayload;
			inputMonitor.notifyAll();
		}
	}

	@Override
	public void onSelectApplication(byte[] responsePayload) {
		synchronized (inputMonitor) {
			this.selectApplicationResponsePayload = responsePayload;

			inputMonitor.notifyAll();
		}
	}

	@Override
	public void onInternalAuthenticate(byte[] commandPayload, byte[] responsePayload) {
		synchronized (inputMonitor) {
			this.internalAuthenticate = new InternalAuthenticate(commandPayload, responsePayload);

			inputMonitor.notifyAll();
		}
	}

	/**
	 * Start processing. Does nothing if the processor already is started, or closed.
	 */

	@Override
	public void start() {
		synchronized (inputMonitor) {
			if (started || close) {
				return;
			}
			started = true;
		}

		try {
			executor.execute(this);
		} catch (RuntimeException e) {
			// not running, and never will: a problem with the verifier
			failure = e;
			close();
			finished.countDown();

			throw e;
		}
	}

	/**
	 * Stop processing, and do not wait for more input. Does nothing if the processor already is closed. The result which has been produced so far is still
	 * available.
	 */

	@Override
	public void close() {
		synchronized (inputMonitor) {
			this.close = true;

			inputMonitor.notifyAll();

			if (!started) {
				// nothing will ever run, so nobody should wait for it
				finished.countDown();
			}
		}

		// those waiting for the algorithm
		synchronized (outputMonitor) {
			outputMonitor.notifyAll();
		}
	}

	/**
	 * Wait for the algorithm of the key of the card to be known.
	 *
	 * @param timeout time to wait in milliseconds, or zero to wait until the algorithm is known or the processor is closed or has finished
	 * @return the algorithm, or null if it is not known (yet)
	 * @throws InterruptedException if interrupted while waiting
	 */

	@Override
	public String waitForAlgorithm(long timeout) throws InterruptedException {
		if (timeout < 0) {
			throw new IllegalArgumentException("timeout must not be negative");
		}
		synchronized (outputMonitor) {
			long until = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeout);

			while (iccKeyAlgorithm == null && !processed && !close) {
				if (timeout > 0) {
					long remaining = until - System.nanoTime();
					if (remaining <= 0) {
						break;
					}
					TimeUnit.NANOSECONDS.timedWait(outputMonitor, remaining);
				} else {
					outputMonitor.wait();
				}
			}
			return iccKeyAlgorithm;
		}
	}

	/**
	 * Wait for the processing to finish, unless it is closed or never started.
	 *
	 * @param timeout time to wait in milliseconds, or zero to wait until the processing is finished
	 * @return the card; if the processing is not finished then a snapshot of it, which will not change
	 * @throws InterruptedException if interrupted while waiting
	 */

	/**
	 * Wait for the processing to finish, and return the card if it was verified. Once the processing has begun, it is waited for also if the processor is
	 * closed, as it then finishes promptly: it stops waiting for input, but completes a verification which it has begun.
	 *
	 * @param timeout time to wait in milliseconds, or zero to wait until the processing is finished
	 * @return the verified card
	 * @throws InterruptedException     if interrupted while waiting
	 * @throws InvalidCardMts7Exception if the card is not valid, or could not be verified (a problem on the card side)
	 * @throws ReaderMts7Exception      if the input is not as a reader following MTS7 provides it, or the card was not completely read, as the processor was
	 *                                  closed or the card was not read in time ({@linkplain MissingCardCommandsException}) (a problem with the reader)
	 * @throws TimeoutException         if the processing did not finish within the timeout (nobody is to blame; try again, or wait longer)
	 * @throws ExecutionException       if the processing failed because of a problem with the verifier, which is the cause: an
	 *                                  {@linkplain no.entur.abt.bob.mts7.api.VerifierMts7Exception} (or a subclass), or anything else (see above)
	 * @throws IllegalStateException    if the processor was never started
	 */

	@Override
	public Mts7Card waitForVerify(long timeout)
			throws InterruptedException, InvalidCardMts7Exception, ReaderMts7Exception, TimeoutException, ExecutionException {
		Mts7Card card = awaitResult(timeout);

		// the processing sets this last, when the card has passed all of its checks
		if (card.isVerifiedPrivateKeyPresent()) {
			return card;
		}

		Exception failure = this.failure;
		if (failure instanceof InvalidCardMts7Exception) {
			throw (InvalidCardMts7Exception) failure;
		}
		if (failure instanceof ReaderMts7Exception) {
			throw (ReaderMts7Exception) failure;
		}
		if (failure != null) {
			throw new ExecutionException("Unable to process the card", failure);
		}

		boolean started;
		boolean close;
		synchronized (inputMonitor) {
			started = this.started;
			close = this.close;
		}
		if (close) {
			// closed before the processing ran, so it never will read the card
			throw new MissingCardCommandsException("The processor was closed before the card was read");
		}
		if (!started) {
			throw new IllegalStateException("The processor was not started");
		}
		throw new TimeoutException("The card was not processed within " + timeout + " ms");
	}

	protected Mts7Card awaitResult(long timeout) throws InterruptedException {
		boolean wait;
		synchronized (inputMonitor) {
			// once closed, the processing finishes promptly if it has begun, and never runs if it has not
			wait = started && (!close || ran);
		}

		if (wait) {
			if (timeout > 0) {
				finished.await(timeout, TimeUnit.MILLISECONDS);
			} else {
				finished.await();
			}
		}

		if (finished.getCount() == 0) {
			// nobody will modify it anymore
			return result;
		}

		synchronized (resultLock) {
			return new Mts7Card(result);
		}
	}

	/**
	 * A change of the result, which may find that the card is not valid.
	 */

	@FunctionalInterface
	protected interface ResultUpdate {
		void accept(Mts7Card card) throws InvalidCardMts7Exception, ReaderMts7Exception;
	}

	/**
	 * Modify the result.
	 *
	 * @param update the change
	 * @throws InvalidCardMts7Exception if the change finds that the card is not valid (a problem on the card side)
	 * @throws ReaderMts7Exception      if the change finds that the input is not as a reader following MTS7 provides it (a problem with the reader)
	 */

	protected void updateResult(ResultUpdate update) throws InvalidCardMts7Exception, ReaderMts7Exception {
		synchronized (resultLock) {
			update.accept(result);
		}
	}

	protected void setIccKeyAlgorithm(String iccKeyAlgorithm) {
		synchronized (outputMonitor) {
			this.iccKeyAlgorithm = iccKeyAlgorithm;

			outputMonitor.notifyAll();
		}
	}

	/**
	 * Wait for input from the card.
	 *
	 * @param available true when the input is available
	 * @return true if the input is available (also if the processor was closed after it arrived), false if the processor was closed or the card was not read in
	 *         time before it arrived, i.e. if there is no point in going on
	 * @throws InterruptedException if interrupted while waiting
	 */

	protected boolean awaitInput(BooleanSupplier available) throws InterruptedException {
		synchronized (inputMonitor) {
			while (!close && !available.getAsBoolean()) {
				long remaining = deadline - System.nanoTime();
				if (remaining <= 0) {
					logger.info("Giving up waiting for input from the card");
					incompleteReason = "The card was not completely read within " + getMaxLifetimeMillis() + " ms";

					return false;
				}
				TimeUnit.NANOSECONDS.timedWait(inputMonitor, remaining);
			}

			// once closed, do not wait for more input, but go on with input which is already there
			if (available.getAsBoolean()) {
				return true;
			}
			logger.info("Closing processor");
			incompleteReason = "The processor was closed before the card was completely read";
			return false;
		}
	}

	/**
	 * Enrich the card with its application-related data (6E): from the select application response, or, as a card need not return it there (MTS7 section
	 * 4.1.1), from GET DATA of it, which the reader then sends before GET (NEXT) DATA of the MTB.
	 *
	 * @param enricher the enricher
	 * @return true if the card was enriched, false if the input stopped (the processor was closed, or the card was not read in time)
	 * @throws InterruptedException     if interrupted while waiting
	 * @throws InvalidCardMts7Exception if the application-related data of the card is malformed or has no valid application identifier (a problem on the card
	 *                                  side)
	 * @throws ReaderMts7Exception      if the reader did not retrieve the application-related data (a problem with the reader)
	 */

	protected boolean enrich(Mts7CardEnricher enricher) throws InterruptedException, InvalidCardMts7Exception, ReaderMts7Exception {
		if (!awaitInput(() -> selectApplicationResponsePayload != null)) {
			return false;
		}
		byte[] selectApplicationResponse = selectApplicationResponsePayload;
		try {
			updateResult(card -> enricher.enrich(card, selectApplicationResponse, null));
		} catch (InsufficientCardCommandsException e) {
			// not in the select application response
			if (!awaitInput(() -> applicationRelatedDataPayload != null || getDataResponsePayload != null)) {
				return false;
			}
			byte[] applicationRelatedData = applicationRelatedDataPayload;
			updateResult(card -> enricher.enrich(card, selectApplicationResponse, applicationRelatedData));
		}
		return true;
	}

	/**
	 * Check the challenge of internal authenticate, before the response of the card to it, as a card may well reject another challenge.
	 *
	 * @param challenge the challenge
	 * @throws MalformedCardCommandException if it is not a SHA-256 hash (MTS7 section 4.1.4) (a problem with the reader)
	 */

	protected static void checkChallenge(byte[] challenge) throws MalformedCardCommandException {
		if (challenge == null || challenge.length != Mts7ApduPayloadsFactory.CHALLENGE_LENGTH) {
			throw new MalformedCardCommandException("Challenge for internal authenticate of " + (challenge == null ? 0 : challenge.length) + " bytes, not "
					+ Mts7ApduPayloadsFactory.CHALLENGE_LENGTH);
		}
	}

	/**
	 * @return true if the input of internal authenticate (command and response) is available
	 */

	boolean isInternalAuthenticateAvailable() {
		InternalAuthenticate input = internalAuthenticate;

		return input != null && input.response != null;
	}

	protected long getMaxLifetimeMillis() {
		return DEFAULT_MAX_LIFETIME_MILLIS;
	}

	/**
	 * Process the input from the card, as it arrives. Use {@linkplain #awaitInput(BooleanSupplier)} for waiting for the input, and
	 * {@linkplain #updateResult(ResultUpdate)} to modify the result. Set {@linkplain Mts7Card#setVerifiedPrivateKeyPresent(boolean)} last, and only when the
	 * card has passed all of the checks.
	 *
	 * @throws InvalidCardMts7Exception if the card is not valid, or could not be verified (a problem on the card side)
	 * @throws Exception                if the processing failed because of a problem with the verifier: an
	 *                                  {@linkplain no.entur.abt.bob.mts7.api.VerifierMts7Exception} (or a subclass)
	 */

	protected abstract void process() throws Exception;

	@Override
	public void run() {
		ran = true;
		deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(getMaxLifetimeMillis());
		try {
			process();

			boolean verified;
			synchronized (resultLock) {
				verified = result.isVerifiedPrivateKeyPresent();
			}
			if (!verified) {
				// the input stopped: not the fault of the card
				String reason = incompleteReason;
				failure = new MissingCardCommandsException(reason != null ? reason : "The card was not completely read");
			}
		} catch (InvalidCardMts7Exception e) {
			logger.info("Invalid card: {}", e.getMessage());

			failure = e;
		} catch (ReaderMts7Exception e) {
			logger.info("Input not as from a reader following MTS7: {}", e.getMessage());

			failure = e;
		} catch (InterruptedException e) {
			// for example when the executor is shut down: a problem with the verifier
			Thread.currentThread().interrupt();

			failure = e;
		} catch (Exception e) {
			// handed over to the thread which waits for the result
			logger.warn("Unable to process the card", e);

			failure = e;
		} finally {
			// notify result waiters
			synchronized (outputMonitor) {
				processed = true;

				outputMonitor.notifyAll();
			}
			finished.countDown();
		}
	}

}
