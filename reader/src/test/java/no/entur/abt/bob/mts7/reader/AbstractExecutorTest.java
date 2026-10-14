package no.entur.abt.bob.mts7.reader;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

/**
 * The executor for the processors is provided by the application, so the tests do the same, and shut it down.
 */

public abstract class AbstractExecutorTest {

	protected ExecutorService executor;

	@BeforeEach
	public void createExecutor() {
		AtomicInteger count = new AtomicInteger();

		// a thread for each processor which runs at the same time, and not keeping the JVM alive if a test goes wrong
		executor = Executors.newCachedThreadPool(r -> {
			Thread thread = new Thread(r, "test-processor-" + count.incrementAndGet());
			thread.setDaemon(true);
			return thread;
		});
	}

	@AfterEach
	public void shutdownExecutor() {
		executor.shutdownNow();
	}

}
