package no.entur.abt.bob.mts7.test.record.bob;

public enum Mts7CardCommandType {

	SELECT_APPLICATION("Select application", 0x00, 0xA4, 0x04, 0x00, 0x06, 0xA0, 0x00, 0x00, 0x07, 0x81, 0x01),
	GET_DATA_COMMAND("Get data", 0x00, 0xCA, 0x7F, 0x21, 0x00, 0x00, 0x00),
	GET_NEXT_DATA_COMMAND("Get next data", 0x00, 0xCC, 0x7F, 0x21, 0x00, 0x00, 0x00),
	INTERNAL_AUTHENTICATE("Internal authenticate", 0x00, 0x88, 0x00, 0x00, 0x20);

	private final String name;
	private final int[] bytes;

	private Mts7CardCommandType(String name, int... bytes) {
		this.name = name;
		this.bytes = bytes;
	}

	public String getName() {
		return name;
	}

	public boolean isCommand(byte[] apdu) {
		for (int i = 0; i < bytes.length && i < apdu.length; i++) {
			if (bytes[i] == -1) {
				continue;
			}
			if (bytes[i] != (apdu[i] & 0xFF)) {
				return false;
			}
		}

		return true;
	}

	public static Mts7CardCommandType parseCommandApdu(byte[] apdu) {
		for (Mts7CardCommandType command : values()) {
			if (command.isCommand(apdu)) {
				return command;
			}
		}

		return null;
	}

	public int[] getBytes() {
		return bytes;
	}

}
