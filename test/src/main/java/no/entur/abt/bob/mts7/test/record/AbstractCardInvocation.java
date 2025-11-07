package no.entur.abt.bob.mts7.test.record;

import java.util.Objects;

public class AbstractCardInvocation implements CardInvocation {

	protected long timestamp;
	protected long duration;
	protected Exception exception;
	protected boolean completed;

	public void setCompleted(boolean completed) {
		this.completed = completed;
	}

	public boolean isCompleted() {
		return completed;
	}

	public long getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}

	public long getDuration() {
		return duration;
	}

	public void setDuration(long duration) {
		this.duration = duration;
	}

	public void completed(long timestamp) {
		this.completed = true;
		this.duration = timestamp - this.timestamp;
	}

	public void setException(Exception exception) {
		this.exception = exception;
	}

	public Exception getException() {
		return exception;
	}

	@Override
	public int hashCode() {
		return Objects.hash(completed, duration, exception, timestamp);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		AbstractCardInvocation other = (AbstractCardInvocation) obj;
		return completed == other.completed && duration == other.duration && Objects.equals(exception, other.exception) && timestamp == other.timestamp;
	}

}
