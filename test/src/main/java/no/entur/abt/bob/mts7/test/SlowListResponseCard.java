package no.entur.abt.bob.mts7.test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import no.entur.abt.bob.mts7.utils.nfc.Card;

public class SlowListResponseCard implements Card {

	private static class Entry {
		public Entry(byte[] commmand, long delay) {
			super();
			this.commmand = commmand;
			this.delay = delay;
		}

		byte[] commmand;
		long delay;
	}

	private List<Entry> commands = new ArrayList<>();
	private int offset = 0;

	@Override
	public byte[] transceive(byte[] data) throws IOException {
		try {
			Entry entry = commands.get(offset);

			try {
				Thread.sleep(entry.delay);
			} catch (InterruptedException e) {
				throw new IOException(e);
			}

			return entry.commmand;
		} finally {
			offset++;
		}
	}

	public void add(byte[] command, long delay) {
		this.commands.add(new Entry(command, delay));
	}

	public long getTotalDelay() {
		long delay = 0;
		for (Entry entry : commands) {
			delay += entry.delay;
		}
		return delay;
	}

}
