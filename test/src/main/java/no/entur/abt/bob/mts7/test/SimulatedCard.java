package no.entur.abt.bob.mts7.test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import no.entur.abt.bob.mts7.test.record.CardRecording;
import no.entur.abt.bob.mts7.test.record.TransceiveInvocation;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;
import no.entur.abt.bob.mts7.utils.nfc.Card;

/**
 * A simulated MTS7 card which returns the MTB in responses of at most <code>maximumResponseLength</code> bytes (or Ne, if less), and the rest using response
 * chaining (61xx and GET RESPONSE). A card which does not support extended length rejects a command with an extended Le with 6700 (wrong length).
 * <p>
 * The commands are recorded, so that a test can check what was sent.
 */

public class SimulatedCard implements Card {

	public static final byte[] WRONG_LENGTH = { 0x67, 0x00 };

	private final byte[] selectApplicationResponse;
	private final boolean extendedLength;
	private final int maximumResponseLength;
	private final byte[] mtb;
	private final byte[] internalAuthenticateResponse;

	private final List<byte[]> commands = new ArrayList<>();

	private int mtbOffset = 0;

	/**
	 * Constructor.
	 *
	 * @param selectApplicationResponse    response APDU to SELECT
	 * @param extendedLength               whether extended length APDUs are supported
	 * @param maximumResponseLength        the maximum number of bytes of the MTB in each response
	 * @param mtb                          the MTB
	 * @param internalAuthenticateResponse response APDU to INTERNAL AUTHENTICATE
	 */

	public SimulatedCard(byte[] selectApplicationResponse, boolean extendedLength, int maximumResponseLength, byte[] mtb, byte[] internalAuthenticateResponse) {
		this.selectApplicationResponse = selectApplicationResponse;
		this.extendedLength = extendedLength;
		this.maximumResponseLength = maximumResponseLength;
		this.mtb = mtb;
		this.internalAuthenticateResponse = internalAuthenticateResponse;
	}

	/**
	 * Constructor with the responses to SELECT and INTERNAL AUTHENTICATE from a recording, i.e. its first and last command.
	 *
	 * @param recording             recording of a card
	 * @param extendedLength        whether extended length APDUs are supported
	 * @param maximumResponseLength the maximum number of bytes of the MTB in each response
	 * @param mtb                   the MTB
	 */

	public SimulatedCard(CardRecording recording, boolean extendedLength, int maximumResponseLength, byte[] mtb) {
		this(recording.getTransceiveInvocations().get(0).getResponse(), extendedLength, maximumResponseLength, mtb, getLastResponse(recording));
	}

	private static byte[] getLastResponse(CardRecording recording) {
		List<TransceiveInvocation> invocations = recording.getTransceiveInvocations();
		return invocations.get(invocations.size() - 1).getResponse();
	}

	@Override
	public byte[] transceive(byte[] command) throws IOException {
		commands.add(command);

		if (isExtendedLength(command) && !extendedLength) {
			return WRONG_LENGTH;
		}

		int ins = command[1] & 0xFF;
		switch (ins) {
		case 0xA4: // select application
			return selectApplicationResponse;
		case 0xCC: // get next data
			mtbOffset = 0;
			return nextMtbPart(command);
		case 0xC0: // get response
			return nextMtbPart(command);
		case 0x88: // internal authenticate
			return internalAuthenticateResponse;
		default:
			throw new IOException("Unexpected command " + ByteArrayHexStringConverter.toHexString(command));
		}
	}

	private byte[] nextMtbPart(byte[] command) {
		int length = Math.min(Math.min(maximumResponseLength, getNe(command)), mtb.length - mtbOffset);
		int remaining = mtb.length - mtbOffset - length;

		byte[] response = new byte[length + 2];
		System.arraycopy(mtb, mtbOffset, response, 0, length);
		mtbOffset += length;

		if (remaining > 0) {
			response[length] = 0x61;
			response[length + 1] = (byte) Math.min(remaining, 0xFF);
		} else {
			response[length] = (byte) 0x90;
			response[length + 1] = 0x00;
		}
		return response;
	}

	/**
	 * @return the commands received so far
	 */

	public List<byte[]> getCommands() {
		return commands;
	}

	/**
	 * An extended length APDU has a zero byte where a short APDU has its Lc or Le (ISO 7816-4 section 5.1), except for a short Le of 0x00 at the end of the
	 * command.
	 *
	 * @param command command APDU
	 * @return true if extended length
	 */

	public static boolean isExtendedLength(byte[] command) {
		return command.length > 5 && command[4] == 0x00;
	}

	/**
	 * The maximum number of bytes expected in the response (Ne) of a command without command data.
	 *
	 * @param command command APDU
	 * @return Ne
	 */

	public static int getNe(byte[] command) {
		if (isExtendedLength(command)) {
			int le = ((command[5] & 0xFF) << 8) | (command[6] & 0xFF);
			return le == 0 ? 65536 : le;
		}
		int le = command[4] & 0xFF;
		return le == 0 ? 256 : le;
	}

}
