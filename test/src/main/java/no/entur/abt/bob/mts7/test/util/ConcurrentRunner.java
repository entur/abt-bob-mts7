package no.entur.abt.bob.mts7.test.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Run the same task on several threads at the same time, for testing that an object can be shared between threads.
 */

public class ConcurrentRunner {

	@FunctionalInterface
	public interface Task {

		/**
		 * @param thread    index of the thread, starting at zero
		 * @param iteration index of the iteration for the thread, starting at zero
		 * @throws Exception if the task failed
		 */

		void run(int thread, int iteration) throws Exception;
	}

	private static final long DEFAULT_TIMEOUT_SECONDS = 60;

	/**
	 * Run the task <code>iterations</code> times on each of <code>threads</code> threads. All threads are released at the same time.
	 *
	 * @param threads    number of threads
	 * @param iterations number of iterations for each thread
	 * @param task       the task
	 * @return the failures (empty if all iterations passed)
	 * @throws InterruptedException if interrupted while waiting
	 */

	public static List<Throwable> run(int threads, int iterations, Task task) throws InterruptedException {
		return run(threads, iterations, task, DEFAULT_TIMEOUT_SECONDS);
	}

	public static List<Throwable> run(int threads, int iterations, Task task, long timeoutSeconds) throws InterruptedException {
		Queue<Throwable> failures = new ConcurrentLinkedQueue<>();

		ExecutorService executor = Executors.newFixedThreadPool(threads);
		try {
			CyclicBarrier barrier = new CyclicBarrier(threads);

			for (int t = 0; t < threads; t++) {
				final int thread = t;
				executor.execute(() -> {
					try {
						barrier.await();

						for (int i = 0; i < iterations; i++) {
							task.run(thread, i);
						}
					} catch (Throwable e) {
						failures.add(e);
					}
				});
			}
			executor.shutdown();

			if (!executor.awaitTermination(timeoutSeconds, TimeUnit.SECONDS)) {
				throw new IllegalStateException("Threads did not complete within " + timeoutSeconds + " seconds");
			}
		} finally {
			executor.shutdownNow();
		}
		return new ArrayList<>(failures);
	}

}
