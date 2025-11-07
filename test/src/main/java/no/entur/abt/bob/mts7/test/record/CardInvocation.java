package no.entur.abt.bob.mts7.test.record;

/**
 *
 * Interface for tracking interesting calls to cards
 *
 */

public interface CardInvocation {

	long getTimestamp();

	void setTimestamp(long timestamp);

	long getDuration();

	void setDuration(long duration);

	void completed(long timestamp);

	void setException(Exception exception);

	boolean isCompleted();

	void setCompleted(boolean completed);

	Exception getException();
}
