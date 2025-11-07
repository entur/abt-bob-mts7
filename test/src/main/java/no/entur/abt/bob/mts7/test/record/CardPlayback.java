package no.entur.abt.bob.mts7.test.record;

import java.io.IOException;
import java.util.List;

import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;
import no.entur.abt.bob.mts7.utils.nfc.Card;

/**
 * Card transceive playback with timing and a few safeguards.
 * 
 */

public class CardPlayback implements Card {

	private final List<CardInvocation> invocations;
	private int offset = 0;
	private boolean ignoreDuration;

	public CardPlayback(List<CardInvocation> invocations) {
		this(invocations, false);
	}

	public CardPlayback(List<CardInvocation> invocations, boolean ignoreDuration) {
		this.invocations = invocations;
		this.ignoreDuration = ignoreDuration;
	}

	@Override
	public byte[] transceive(byte[] data) throws IOException {
		if (offset < invocations.size()) {
			CardInvocation cardInvocation = invocations.get(offset);
			offset++;

			if (!ignoreDuration) {
				long duration = cardInvocation.getDuration();
				try {
					Thread.sleep(duration / 1000_000, (int) (duration % 1000_000));
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();

					throw new RuntimeException();
				}
			}

			if (cardInvocation instanceof TransceiveInvocation) {
				TransceiveInvocation transceiveInvocation = (TransceiveInvocation) cardInvocation;

				byte[] command = transceiveInvocation.getCommand();

				// add rudimentary safeguard
				if (data[0] != command[0] || data[1] != command[1]) {
					throw new IllegalStateException("Expected command start CLA + INS " + ByteArrayHexStringConverter.toHexString(command, 0, 2) + ", got "
							+ ByteArrayHexStringConverter.toHexString(data, 0, 2));
				}

				if (transceiveInvocation.response != null) {
					return transceiveInvocation.response;
				}
				if (transceiveInvocation.exception instanceof IOException) {
					throw new IOException();
				}
			}
		}
		throw new IllegalStateException();
	}

	public List<CardInvocation> getInvocations() {
		return invocations;
	}

}
