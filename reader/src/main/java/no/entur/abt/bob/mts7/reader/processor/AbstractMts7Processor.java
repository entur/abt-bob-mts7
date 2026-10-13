package no.entur.abt.bob.mts7.reader.processor;

import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import no.entur.abt.bob.mts7.core.Mts7Card;

/**
 * Base class for processors: the part which is about running alongside the card reader, i.e. receiving what the reader gets from the card on one thread, and
 * processing it on another.
 *
 * <p>
 * A processor is for a single card, so it must not be reused. The methods which receive the input from the card, {@linkplain #close()} and the methods which
 * wait for the result can be called from any thread, any number of times. The processing itself is done by {@linkplain #run()} (which is called by the
 * executor when the processor is started), and reads the input in the order in which it is needed, so the card reader can give the processor its input as soon
 * as it has it.
 *
 * <p>
 * The processing waits for input from the card, so it needs a thread to itself while it does: an executor which cannot run all of the processors which are
 * started at the same time (a bounded pool, or one which runs the task on the calling thread) will make them wait for each other.
 *
 * <p>
 * The executor is always provided by the application, which owns it and so is the one to shut it down; nothing in this library creates an executor or a thread
 * of its own. As a processor stops waiting for the card after {@linkplain #DEFAULT_MAX_LIFETIME_MILLIS}, its thread is never blocked for much longer than
 * that, but the threads of the executor are not daemon threads unless the application makes them so.
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

	protected volatile byte[] internalAuthenticateResponsePayload;
	protected volatile byte[] internalAuthenticateCommandPayload;

	// never null, so that waitForVerify(..) can report on a processor which did not get any input. Only modify it using updateResult(..)
	protected final Mts7Card result = new Mts7Card();
	private final Object resultLock = new Object();

	protected volatile String iccKeyAlgorithm;

	private final Executor executor;

	// guarded by the input monitor
	private boolean started;

	// guarded by the output monitor
	private boolean processed;

	// when the processing is done (successfully or not), also if it never was started
	private final CountDownLatch finished = new CountDownLatch(1);

	private volatile long deadline;

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
	public void onSelectApplication(byte[] responsePayload) {
		synchronized (inputMonitor) {
			this.selectApplicationResponsePayload = responsePayload;

			inputMonitor.notifyAll();
		}
	}

	@Override
	public void onInternalAuthenticate(byte[] commandPayload, byte[] responsePayload) {
		synchronized (inputMonitor) {
			this.internalAuthenticateCommandPayload = commandPayload;
			this.internalAuthenticateResponsePayload = responsePayload;

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
			// not running, and never will
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

	protected Mts7Card awaitResult(long timeout) throws InterruptedException {
		boolean wait;
		synchronized (inputMonitor) {
			wait = started && !close;
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

	protected void updateResult(Consumer<Mts7Card> update) {
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
	 * @return true if the input is available, false if the processor was closed or the card was not read in time, i.e. if there is no point in going on
	 * @throws InterruptedException if interrupted while waiting
	 */

	protected boolean awaitInput(BooleanSupplier available) throws InterruptedException {
		synchronized (inputMonitor) {
			while (!close && !available.getAsBoolean()) {
				long remaining = deadline - System.nanoTime();
				if (remaining <= 0) {
					logger.info("Giving up waiting for input from the card");

					return false;
				}
				TimeUnit.NANOSECONDS.timedWait(inputMonitor, remaining);
			}

			if (close) {
				logger.info("Closing processor");
			}
			return !close;
		}
	}

	protected long getMaxLifetimeMillis() {
		return DEFAULT_MAX_LIFETIME_MILLIS;
	}

	/**
	 * Process the input from the card, as it arrives. Use {@linkplain #awaitInput(BooleanSupplier)} for waiting for the input, and
	 * {@linkplain #updateResult(Consumer)} to modify the result.
	 *
	 * @throws Exception if the processing failed
	 */

	protected abstract void process() throws Exception;

	@Override
	public void run() {
		deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(getMaxLifetimeMillis());
		try {
			process();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		} catch (Exception e) {
			logger.info("Problem processing files", e);
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
