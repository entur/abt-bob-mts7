package no.entur.abt.bob.mts7.test.record;

import java.util.ArrayList;
import java.util.List;

/**
 * Records the invocations of a single card. The list can be added to and read from different threads, but the invocations themselves are completed by the
 * thread which made the invocation.
 */

public class CardInvocationRecorder implements CardInvocationListener {

	private final List<CardInvocation> invocations = new ArrayList<>(64);

	@Override
	public ConnectInvocation onConnect() {
		ConnectInvocation connectInvocation = new ConnectInvocation();
		connectInvocation.setTimestamp(System.nanoTime());
		return connectInvocation;
	}

	@Override
	public CloseInvocation onClose() {
		CloseInvocation invocation = new CloseInvocation();
		invocation.setTimestamp(System.nanoTime());
		return invocation;
	}

	@Override
	public TransceiveInvocation onTransceive(byte[] command) {
		TransceiveInvocation transceive = new TransceiveInvocation();
		transceive.setCommand(command);
		transceive.setTimestamp(System.nanoTime());
		synchronized (invocations) {
			this.invocations.add(transceive);
		}
		return transceive;
	}

	/**
	 * @return the invocations so far
	 */

	public List<CardInvocation> getInvocations() {
		synchronized (invocations) {
			return new ArrayList<>(invocations);
		}
	}
}
