package no.entur.abt.bob.mts7.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * The outcome of {@linkplain Mts7Warmup#warmUp()}. Warming up is best effort and never throws, so this is the place to look for what did not work.
 */

public class Mts7WarmupResult {

	private final int iterations;
	private final long elapsedNanos;
	private final List<Exception> failures;

	public Mts7WarmupResult(int iterations, long elapsedNanos, List<Exception> failures) {
		this.iterations = iterations;
		this.elapsedNanos = elapsedNanos;
		this.failures = Collections.unmodifiableList(new ArrayList<>(failures));
	}

	/**
	 * @return the number of times the sample card was run through the factories, which is less than requested if the duration ran out or a factory failed
	 */

	public int getIterations() {
		return iterations;
	}

	public long getElapsedNanos() {
		return elapsedNanos;
	}

	public long getElapsed(TimeUnit unit) {
		return unit.convert(elapsedNanos, TimeUnit.NANOSECONDS);
	}

	/**
	 * @return what did not work (keys which could not be created, factories which did not process the sample card), empty if everything did
	 */

	public List<Exception> getFailures() {
		return failures;
	}

	public boolean isSuccess() {
		return failures.isEmpty();
	}

	@Override
	public String toString() {
		return "Mts7WarmupResult [iterations=" + iterations + ", elapsed=" + getElapsed(TimeUnit.MILLISECONDS) + "ms, failures=" + failures.size() + "]";
	}

}
