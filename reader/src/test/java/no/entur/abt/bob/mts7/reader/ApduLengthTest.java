package no.entur.abt.bob.mts7.reader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.api.UnexpectedCardResponseException;
import no.entur.abt.bob.mts7.core.LenientMts7ApduPayloadsFactory;
import no.entur.abt.bob.mts7.core.Mts7ApduPayloads;
import no.entur.abt.bob.mts7.core.Mts7ApduPayloadsFactory;
import no.entur.abt.bob.mts7.core.VerifyKeyPairMts7CardFactory;
import no.entur.abt.bob.mts7.reader.processor.Mts7Processor;
import no.entur.abt.bob.mts7.reader.processor.VerifyKeyPairMts7ProcessorFactory;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchanges;
import no.entur.abt.bob.mts7.simple.reader.Mts7ApduExchangesFactory;
import no.entur.abt.bob.mts7.simple.reader.Mts7Exchange;
import no.entur.abt.bob.mts7.test.record.CardInvocation;
import no.entur.abt.bob.mts7.test.record.CardPlayback;
import no.entur.abt.bob.mts7.test.record.CardRecording;
import no.entur.abt.bob.mts7.test.record.CardRecordingFactory;
import no.entur.abt.bob.mts7.test.record.TransceiveInvocation;
import no.entur.abt.bob.mts7.test.util.MockRandomFactory;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * The reader sends GET NEXT DATA with an extended Le, which saves GET RESPONSE round trips for cards which support extended length. Extended length support is
 * optional for the PICC (MTS7 section 3.1.4), and a PICC which does not support it rejects the command with 6700 (wrong length). Then the reader repeats the
 * command with a short Le, and reads the rest of a longer response using response chaining (MTS7 section 2.1).
 * <p>
 * The cards seen so far are replayed from recordings (see {@linkplain CardRecordingIntegrationTest}). The cases which these cards do not cover are simulated,
 * using data from the recordings.
 */

public class ApduLengthTest extends AbstractExecutorTest {

	private static final byte[] GET_NEXT_DATA_EXTENDED_LENGTH = Mts7ApduExchangesFactory.GET_NEXT_DATA_COMMAND;
	private static final byte[] GET_NEXT_DATA_SHORT_LENGTH = Mts7ApduExchangesFactory.GET_NEXT_DATA_SHORT_LENGTH_COMMAND;
	private static final byte[] GET_RESPONSE_SHORT_LENGTH = Mts7ApduExchangesFactory.GET_RESPONSE_SHORT_LENGTH_COMMAND;

	private static final byte[] WRONG_LENGTH = { 0x67, 0x00 };
	private static final byte[] REFERENCED_DATA_NOT_FOUND = { 0x6A, (byte) 0x88 };

	// accepts an extended Le, and returns the whole MTB (258 bytes) in a single response
	private static CardRecording participant10;

	// rejects an extended Le with 6700, and returns the MTB (232 bytes) in a single response to a short Le
	private static CardRecording participant36;

	@BeforeAll
	public static void readRecordings() throws Exception {
		CardRecordingFactory factory = new CardRecordingFactory();

		participant10 = factory.read("/recordings/participant-10.json");
		participant36 = factory.read("/recordings/participant-36.json");
	}

	private static List<TransceiveInvocation> getTransceiveInvocations(CardRecording recording) {
		List<TransceiveInvocation> result = new ArrayList<>();
		for (CardInvocation invocation : recording.getInvocations()) {
			if (invocation instanceof TransceiveInvocation) {
				result.add((TransceiveInvocation) invocation);
			}
		}
		return result;
	}

	private static byte[] getResponse(CardRecording recording, int index) {
		return getTransceiveInvocations(recording).get(index).getResponse();
	}

	/**
	 * Replay a recording. The playback only checks the start of each command, so check that the reader sends exactly the recorded commands; with the recorded
	 * random value the challenge of internal authenticate is the same too.
	 */

	private static class RecordedCard implements Mts7Exchange {

		private final CardPlayback playback;
		private final List<TransceiveInvocation> recorded;

		private int index = 0;

		public RecordedCard(CardRecording recording) {
			this.playback = recording.toPlayback(true);
			this.recorded = getTransceiveInvocations(recording);
		}

		@Override
		public byte[] getTagId() {
			return null;
		}

		@Override
		public byte[] transceive(byte[] command) throws IOException {
			if (index >= recorded.size()) {
				throw new IOException("Unexpected command " + ByteArrayHexStringConverter.toHexString(command) + " after the recorded commands");
			}
			byte[] expected = recorded.get(index).getCommand();
			if (!Arrays.equals(expected, command)) {
				throw new IOException(
						"Expected command " + ByteArrayHexStringConverter.toHexString(expected) + ", got " + ByteArrayHexStringConverter.toHexString(command));
			}
			index++;

			return playback.transceive(command);
		}

		public void assertAllCommandsSent() {
			assertEquals(recorded.size(), index, "commands sent");
		}
	}

	/**
	 * A card which returns the MTB in responses of at most <code>maximumResponseLength</code> bytes (or Ne, if less), and the rest using response chaining
	 * (61xx and GET RESPONSE). A card which does not support extended length rejects a command with an extended Le with 6700.
	 */

	private static class SimulatedCard implements Mts7Exchange {

		private final byte[] selectApplicationResponse;
		private final boolean extendedLength;
		private final int maximumResponseLength;
		private final byte[] mtb;
		private final byte[] internalAuthenticateResponse;

		private final List<byte[]> commands = new ArrayList<>();

		private int mtbOffset = 0;

		public SimulatedCard(CardRecording recording, boolean extendedLength, int maximumResponseLength, byte[] mtb) {
			List<TransceiveInvocation> invocations = getTransceiveInvocations(recording);

			this.selectApplicationResponse = invocations.get(0).getResponse();
			this.internalAuthenticateResponse = invocations.get(invocations.size() - 1).getResponse();
			this.extendedLength = extendedLength;
			this.maximumResponseLength = maximumResponseLength;
			this.mtb = mtb;
		}

		@Override
		public byte[] getTagId() {
			return null;
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

		public List<byte[]> getCommands() {
			return commands;
		}
	}

	/**
	 * An extended length APDU has a zero byte where a short APDU has its Lc or Le (ISO 7816-4 section 5.1), except for a short Le of 0x00 at the end of the
	 * command.
	 */

	private static boolean isExtendedLength(byte[] command) {
		return command.length > 5 && command[4] == 0x00;
	}

	/**
	 * The maximum number of bytes expected in the response (Ne) of a command without command data.
	 */

	private static int getNe(byte[] command) {
		if (isExtendedLength(command)) {
			int le = ((command[5] & 0xFF) << 8) | (command[6] & 0xFF);
			return le == 0 ? 65536 : le;
		}
		int le = command[4] & 0xFF;
		return le == 0 ? 256 : le;
	}

	private Mts7ApduExchanges read(Mts7Exchange card, Random random) throws Exception {
		return new Mts7ApduExchangesFactory(random).createCard(card, null);
	}

	private Mts7ApduExchanges readWithProcessor(Mts7Exchange card, Random random) throws Exception {
		Mts7Processor processor = new VerifyKeyPairMts7ProcessorFactory(executor).create();
		try {
			return new ProcessorMts7ApduExchangesFactory(random).create(card, processor, null);
		} finally {
			processor.close();
		}
	}

	private static Random random() {
		return MockRandomFactory.newInstance(new byte[32]);
	}

	/**
	 * Check that the commands between select and internal authenticate are as expected, and that the MTB is read in full from the recorded exchanges.
	 */

	private static void assertRead(List<byte[]> commands, Mts7ApduExchanges exchanges, byte[] mtb, byte[]... expectedCommands) throws Exception {
		// select, the expected commands, internal authenticate
		assertEquals(expectedCommands.length + 2, commands.size());
		for (int i = 0; i < expectedCommands.length; i++) {
			assertArrayEquals(expectedCommands[i], commands.get(i + 1), "command " + (i + 1));
		}
		assertEquals(0x88, commands.get(commands.size() - 1)[1] & 0xFF);

		assertEquals(commands.size(), exchanges.getExchanges().size());
		assertArrayEquals(mtb, new Mts7ApduPayloadsFactory().createCard(exchanges).getGetDataOutput());
		assertArrayEquals(mtb, new LenientMts7ApduPayloadsFactory().createCard(exchanges).getGetDataOutput());
	}

	/**
	 * Replay the recording with both the plain and the processor based reader, and check that the MTB is read and that the private key of the card is verified.
	 */

	private void assertRecordingRead(CardRecording recording, byte[]... expectedCommands) throws Exception {
		List<TransceiveInvocation> invocations = getTransceiveInvocations(recording);

		// the response to the last get next data, without the status bytes
		byte[] getNextDataResponse = invocations.get(invocations.size() - 2).getResponse();
		byte[] mtb = Arrays.copyOf(getNextDataResponse, getNextDataResponse.length - 2);

		List<byte[]> recordedCommands = new ArrayList<>();
		for (TransceiveInvocation invocation : invocations) {
			recordedCommands.add(invocation.getCommand());
		}

		RecordedCard card = new RecordedCard(recording);
		Mts7ApduExchanges exchanges = read(card, MockRandomFactory.newInstance(recording.getRandomValue()));
		card.assertAllCommandsSent();
		assertRead(recordedCommands, exchanges, mtb, expectedCommands);
		assertVerifiedPrivateKey(exchanges);

		RecordedCard processorCard = new RecordedCard(recording);
		Mts7ApduExchanges processorExchanges = readWithProcessor(processorCard, MockRandomFactory.newInstance(recording.getRandomValue()));
		processorCard.assertAllCommandsSent();
		assertRead(recordedCommands, processorExchanges, mtb, expectedCommands);
		assertVerifiedPrivateKey(processorExchanges);
	}

	private static void assertVerifiedPrivateKey(Mts7ApduExchanges exchanges) throws Exception {
		Mts7ApduPayloads payloads = new Mts7ApduPayloadsFactory().createCard(exchanges);

		assertTrue(new VerifyKeyPairMts7CardFactory().create(payloads).isVerifiedPrivateKeyPresent());
	}

	@Test
	public void testParticipant10Card() throws Exception {
		// extended length, so the whole MTB in a single response
		assertRecordingRead(participant10, GET_NEXT_DATA_EXTENDED_LENGTH);
	}

	@Test
	public void testParticipant36Card() throws Exception {
		// rejected extended length, then short length with an MTB which fits in a single response
		assertRecordingRead(participant36, GET_NEXT_DATA_EXTENDED_LENGTH, GET_NEXT_DATA_SHORT_LENGTH);
	}

	@Test
	public void testCardWithoutExtendedLengthSupportAndLongMtb() throws Exception {
		// like the participant 36 card, but with the longer MTB of the participant 10 card, which needs response chaining, also with short length
		byte[] getNextDataResponse = getResponse(participant10, 1);
		byte[] mtb = Arrays.copyOf(getNextDataResponse, getNextDataResponse.length - 2);
		assertEquals(258, mtb.length);

		SimulatedCard card = new SimulatedCard(participant36, false, 256, mtb);
		assertRead(card.getCommands(), read(card, random()), mtb, GET_NEXT_DATA_EXTENDED_LENGTH, GET_NEXT_DATA_SHORT_LENGTH, GET_RESPONSE_SHORT_LENGTH);

		SimulatedCard processorCard = new SimulatedCard(participant36, false, 256, mtb);
		assertRead(processorCard.getCommands(), readWithProcessor(processorCard, random()), mtb, GET_NEXT_DATA_EXTENDED_LENGTH, GET_NEXT_DATA_SHORT_LENGTH,
				GET_RESPONSE_SHORT_LENGTH);
	}

	/**
	 * A card which rejects both extended and short length is not tried again.
	 */

	private static class WrongLengthCard extends SimulatedCard {

		public WrongLengthCard() {
			super(participant36, false, 256, new byte[0]);
		}

		@Override
		public byte[] transceive(byte[] command) throws IOException {
			if ((command[1] & 0xFF) == 0xCC) {
				getCommands().add(command);
				return WRONG_LENGTH;
			}
			return super.transceive(command);
		}
	}

	@Test
	public void testCardWhichRejectsShortLength() throws Exception {
		WrongLengthCard card = new WrongLengthCard();
		UnexpectedCardResponseException e = assertThrows(UnexpectedCardResponseException.class, () -> read(card, random()));
		assertArrayEquals(GET_NEXT_DATA_SHORT_LENGTH, e.getCommand());
		assertEquals(3, card.getCommands().size());

		WrongLengthCard processorCard = new WrongLengthCard();
		e = assertThrows(UnexpectedCardResponseException.class, () -> readWithProcessor(processorCard, random()));
		assertArrayEquals(GET_NEXT_DATA_SHORT_LENGTH, e.getCommand());
		assertEquals(3, processorCard.getCommands().size());
	}

	/**
	 * Other errors than wrong length are not a reason to try short length.
	 */

	private static class NoMtbCard extends SimulatedCard {

		public NoMtbCard() {
			super(participant10, true, 1024, new byte[0]);
		}

		@Override
		public byte[] transceive(byte[] command) throws IOException {
			if ((command[1] & 0xFF) == 0xCC) {
				getCommands().add(command);
				return REFERENCED_DATA_NOT_FOUND;
			}
			return super.transceive(command);
		}
	}

	@Test
	public void testCardWithoutMtb() throws Exception {
		NoMtbCard card = new NoMtbCard();
		UnexpectedCardResponseException e = assertThrows(UnexpectedCardResponseException.class, () -> read(card, random()));
		assertArrayEquals(GET_NEXT_DATA_EXTENDED_LENGTH, e.getCommand());
		assertEquals(2, card.getCommands().size());

		NoMtbCard processorCard = new NoMtbCard();
		e = assertThrows(UnexpectedCardResponseException.class, () -> readWithProcessor(processorCard, random()));
		assertArrayEquals(GET_NEXT_DATA_EXTENDED_LENGTH, e.getCommand());
		assertEquals(2, processorCard.getCommands().size());
	}

}
