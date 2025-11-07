package no.entur.abt.bob.mts7.test.record;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class CardRecording {

	private Instant timestamp;
	private byte[] randomValue;
	private LocalDateTime dateTime;

	private List<CardInvocation> invocations;

	public List<CardInvocation> getInvocations() {
		return invocations;
	}

	public void setInvocations(List<CardInvocation> invocations) {
		this.invocations = invocations;
	}

	public void setRandomValue(byte[] randomValue) {
		this.randomValue = randomValue;
	}

	public byte[] getRandomValue() {
		return randomValue;
	}

	public CardPlayback toPlayback() {
		return new CardPlayback(invocations);
	}

	public CardPlayback toPlayback(boolean ignoreDuration) {
		return new CardPlayback(invocations, ignoreDuration);
	}

	public LocalDateTime getDateTime() {
		return dateTime;
	}

	public void setDateTime(LocalDateTime dateTime) {
		this.dateTime = dateTime;
	}

	public void setTimestamp(Instant timestamp) {
		this.timestamp = timestamp;
	}

	public Instant getTimestamp() {
		return timestamp;
	}

	public void add(CardInvocation invocation) {
		if (invocations == null) {
			invocations = new ArrayList<>();
		}
		this.invocations.add(invocation);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(randomValue);
		result = prime * result + Objects.hash(dateTime, invocations, timestamp);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		CardRecording other = (CardRecording) obj;
		return Objects.equals(dateTime, other.dateTime) && Objects.equals(invocations, other.invocations) && Arrays.equals(randomValue, other.randomValue)
				&& Objects.equals(timestamp, other.timestamp);
	}

}
