package no.entur.abt.bob.mts7.test.record;

import java.util.ArrayList;
import java.util.List;

public class AbstractCardRecordingAnalyzer {

	protected static class CardCommandIdentifier {

		private String name;
		private int[] bytes;

		public CardCommandIdentifier(String name, int... bytes) {
			super();
			this.name = name;
			this.bytes = bytes;
		}

		public boolean isCommand(byte[] apdu) {
			for (int i = 0; i < bytes.length; i++) {
				if (bytes[i] == -1) {
					continue;
				}
				if (bytes[i] != apdu[i]) {
					return false;
				}
			}

			return true;
		}
	}

	protected List<CardCommandIdentifier> commandIdentifiers = new ArrayList<>();

	public List<CardCommandIdentifier> getCommandIdentifiers() {
		return commandIdentifiers;
	}

	public void addCommandIdentifier(int cla, int ins, String name) {
		addCommandIdentifier(cla, ins, name);
	}

	public void addCommandIdentifier(int[] bytes, String name) {
		commandIdentifiers.add(new CardCommandIdentifier(name, bytes));
	}

	public void addCommandIdentifier(int cla, int ins, int p1, int p2, String name) {
		commandIdentifiers.add(new CardCommandIdentifier(name, cla, ins, p1, p2));
	}

	protected String getCommandName(byte[] command) {
		for (CardCommandIdentifier commandIdentifier : commandIdentifiers) {
			if (commandIdentifier.isCommand(command)) {
				return commandIdentifier.name;
			}
		}
		return null;
	}

}
