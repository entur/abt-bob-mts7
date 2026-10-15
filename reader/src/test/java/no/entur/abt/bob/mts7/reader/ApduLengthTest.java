package no.entur.abt.bob.mts7.reader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.api.UnexpectedCardResponseException;
import no.entur.abt.bob.mts7.core.LenientMts7ApduPayloadsFactory;
import no.entur.abt.bob.mts7.core.Mts7ApduPayloadsFactory;
import no.entur.abt.bob.mts7.reader.processor.Mts7Processor;
import no.entur.abt.bob.mts7.reader.processor.VerifyKeyPairMts7ProcessorFactory;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchanges;
import no.entur.abt.bob.mts7.simple.reader.Mts7ApduExchangesFactory;
import no.entur.abt.bob.mts7.simple.reader.Mts7Exchange;
import no.entur.abt.bob.mts7.test.util.MockRandomFactory;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * The reader sends GET NEXT DATA with an extended Le, which saves GET RESPONSE round trips for cards which support extended length. Extended length support is
 * optional for the PICC (MTS7 section 3.1.4), and a PICC which does not support it rejects the command with 6700 (wrong length). Then the reader repeats the
 * command with a short Le, and reads the rest of a longer response using response chaining (MTS7 section 2.1).
 * <p>
 * The simulated cards behave like the cards seen so far.
 */

public class ApduLengthTest extends AbstractExecutorTest {

	private static final byte[] GET_NEXT_DATA_EXTENDED_LENGTH = Mts7ApduExchangesFactory.GET_NEXT_DATA_COMMAND;
	private static final byte[] GET_NEXT_DATA_SHORT_LENGTH = Mts7ApduExchangesFactory.GET_NEXT_DATA_SHORT_LENGTH_COMMAND;
	private static final byte[] GET_RESPONSE_SHORT_LENGTH = Mts7ApduExchangesFactory.GET_RESPONSE_SHORT_LENGTH_COMMAND;

	// participant 10, as recorded: Extended Length Information (7F66) with maximum command and response APDU lengths of 261 and 258 bytes
	private static final byte[] PARTICIPANT_10_SELECT_APPLICATION_RESPONSE = ByteArrayHexStringConverter
			.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");

	// participant 36 (with a made up serial number): maximum command and response APDU lengths of 256 bytes
	private static final byte[] PARTICIPANT_36_SELECT_APPLICATION_RESPONSE = ByteArrayHexStringConverter
			.hexStringToByteArray("64296E274F10A00000078101010024000000000000017A0593030000008A01057F660802020100020201009000");

	// genuine MTB (without the status words) issued by participant 10, 258 bytes
	private static final byte[] MTB = ByteArrayHexStringConverter.hexStringToByteArray(
			"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C4603");

	// as long as the MTB of the participant 36 card (232 bytes), so that it fits in a single short response; the contents are not used
	private static final byte[] SHORT_MTB = Arrays.copyOf(MTB, 232);

	private static final byte[] SIGNATURE_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");

	private static final byte[] WRONG_LENGTH = { 0x67, 0x00 };
	private static final byte[] REFERENCED_DATA_NOT_FOUND = { 0x6A, (byte) 0x88 };

	/**
	 * A card which returns the MTB in responses of at most <code>maximumResponseLength</code> bytes (or Ne, if less), and the rest using response chaining
	 * (61xx and GET RESPONSE). A card which does not support extended length rejects a command with an extended Le with 6700.
	 */

	private static class SimulatedCard implements Mts7Exchange {

		private final byte[] selectApplicationResponse;
		private final boolean extendedLength;
		private final int maximumResponseLength;
		private final byte[] mtb;

		private final List<byte[]> commands = new ArrayList<>();

		private int mtbOffset = 0;

		public SimulatedCard(byte[] selectApplicationResponse, boolean extendedLength, int maximumResponseLength, byte[] mtb) {
			this.selectApplicationResponse = selectApplicationResponse;
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
				return SIGNATURE_RESPONSE;
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
	 * Participant 10: accepts an extended Le, and returns the whole MTB in a single response, as recorded.
	 */

	private static SimulatedCard participant10Card() {
		return new SimulatedCard(PARTICIPANT_10_SELECT_APPLICATION_RESPONSE, true, 1024, MTB);
	}

	/**
	 * Participant 36: rejects an extended Le with 6700, and returns at most 256 bytes in each response.
	 */

	private static SimulatedCard participant36Card(byte[] mtb) {
		return new SimulatedCard(PARTICIPANT_36_SELECT_APPLICATION_RESPONSE, false, 256, mtb);
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

	private Random random() {
		return MockRandomFactory.newInstance(new byte[32]);
	}

	private Mts7ApduExchanges read(SimulatedCard card) throws Exception {
		return new Mts7ApduExchangesFactory(random()).createCard(card, null);
	}

	private Mts7ApduExchanges readWithProcessor(SimulatedCard card) throws Exception {
		Mts7Processor processor = new VerifyKeyPairMts7ProcessorFactory(executor).create();
		try {
			return new ProcessorMts7ApduExchangesFactory(random()).create(card, processor, null);
		} finally {
			processor.close();
		}
	}

	/**
	 * Check that the MTB is read in full, both by the reader and from the recorded exchanges, and that the commands up to internal authenticate are as
	 * expected.
	 */

	private void assertRead(SimulatedCard card, Mts7ApduExchanges exchanges, byte[] mtb, byte[]... expectedCommands) throws Exception {
		List<byte[]> commands = card.getCommands();

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

	@Test
	public void testParticipant10Card() throws Exception {
		// extended length, so the whole MTB in a single response
		SimulatedCard card = participant10Card();
		assertRead(card, read(card), MTB, GET_NEXT_DATA_EXTENDED_LENGTH);

		SimulatedCard processorCard = participant10Card();
		assertRead(processorCard, readWithProcessor(processorCard), MTB, GET_NEXT_DATA_EXTENDED_LENGTH);
	}

	@Test
	public void testParticipant36Card() throws Exception {
		// rejected extended length, then short length with an MTB which fits in a single response
		SimulatedCard card = participant36Card(SHORT_MTB);
		assertRead(card, read(card), SHORT_MTB, GET_NEXT_DATA_EXTENDED_LENGTH, GET_NEXT_DATA_SHORT_LENGTH);

		SimulatedCard processorCard = participant36Card(SHORT_MTB);
		assertRead(processorCard, readWithProcessor(processorCard), SHORT_MTB, GET_NEXT_DATA_EXTENDED_LENGTH, GET_NEXT_DATA_SHORT_LENGTH);
	}

	@Test
	public void testParticipant36CardWithLongMtb() throws Exception {
		// rejected extended length, then short length with an MTB which needs response chaining, also with short length
		SimulatedCard card = participant36Card(MTB);
		assertRead(card, read(card), MTB, GET_NEXT_DATA_EXTENDED_LENGTH, GET_NEXT_DATA_SHORT_LENGTH, GET_RESPONSE_SHORT_LENGTH);

		SimulatedCard processorCard = participant36Card(MTB);
		assertRead(processorCard, readWithProcessor(processorCard), MTB, GET_NEXT_DATA_EXTENDED_LENGTH, GET_NEXT_DATA_SHORT_LENGTH, GET_RESPONSE_SHORT_LENGTH);
	}

	/**
	 * A card which rejects both extended and short length is not tried again.
	 */

	private static class WrongLengthCard extends SimulatedCard {

		public WrongLengthCard() {
			super(PARTICIPANT_36_SELECT_APPLICATION_RESPONSE, false, 256, MTB);
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
		UnexpectedCardResponseException e = assertThrows(UnexpectedCardResponseException.class, () -> read(card));
		assertArrayEquals(GET_NEXT_DATA_SHORT_LENGTH, e.getCommand());
		assertEquals(3, card.getCommands().size());

		WrongLengthCard processorCard = new WrongLengthCard();
		e = assertThrows(UnexpectedCardResponseException.class, () -> readWithProcessor(processorCard));
		assertArrayEquals(GET_NEXT_DATA_SHORT_LENGTH, e.getCommand());
		assertEquals(3, processorCard.getCommands().size());
	}

	/**
	 * Other errors than wrong length are not a reason to try short length.
	 */

	private static class NoMtbCard extends SimulatedCard {

		public NoMtbCard() {
			super(PARTICIPANT_10_SELECT_APPLICATION_RESPONSE, true, 1024, MTB);
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
		UnexpectedCardResponseException e = assertThrows(UnexpectedCardResponseException.class, () -> read(card));
		assertArrayEquals(GET_NEXT_DATA_EXTENDED_LENGTH, e.getCommand());
		assertEquals(2, card.getCommands().size());

		NoMtbCard processorCard = new NoMtbCard();
		e = assertThrows(UnexpectedCardResponseException.class, () -> readWithProcessor(processorCard));
		assertArrayEquals(GET_NEXT_DATA_EXTENDED_LENGTH, e.getCommand());
		assertEquals(2, processorCard.getCommands().size());
	}

}
