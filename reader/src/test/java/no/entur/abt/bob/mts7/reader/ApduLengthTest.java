package no.entur.abt.bob.mts7.reader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.core.Mts7ApduPayloadsFactory;
import no.entur.abt.bob.mts7.reader.processor.Mts7Processor;
import no.entur.abt.bob.mts7.reader.processor.VerifyKeyPairMts7ProcessorFactory;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchanges;
import no.entur.abt.bob.mts7.simple.reader.Mts7ApduExchangesFactory;
import no.entur.abt.bob.mts7.simple.reader.Mts7Exchange;
import no.entur.abt.bob.mts7.test.util.MockRandomFactory;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * Support for extended length APDUs is optional for the PICC, and indicated by the Extended Length Information (MTS7 section 3.1.4). A PICC which does not
 * support it rejects an extended Le with 6700 (wrong length). The reader must therefore use short APDUs and response chaining (MTS7 section 2.1), unless the
 * PICC indicates that it can return more in a single response APDU, in which case extended length APDUs save GET RESPONSE round trips.
 */

public class ApduLengthTest extends AbstractExecutorTest {

	// the response to SELECT, up to the maximum APDU lengths of the Extended Length Information (7F66)
	private static final String SELECT_APPLICATION_RESPONSE_PREFIX = "64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F66080202";

	// genuine MTB (without the status words), 258 bytes
	private static final byte[] MTB = ByteArrayHexStringConverter.hexStringToByteArray(
			"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C4603");

	private static final byte[] SIGNATURE_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");

	private static final byte[] WRONG_LENGTH = { 0x67, 0x00 };

	private static byte[] selectApplicationResponse(int maximumCommandApduLength, int maximumResponseApduLength) {
		return ByteArrayHexStringConverter.hexStringToByteArray(
				SELECT_APPLICATION_RESPONSE_PREFIX + String.format("%04X0202%04X9000", maximumCommandApduLength, maximumResponseApduLength));
	}

	/**
	 * A card which returns the MTB in parts of at most <code>maximumResponseLength</code> bytes (or less, if the Le of the command says so), and the rest using
	 * response chaining (61xx and GET RESPONSE). A card which does not support extended length APDUs rejects a command with an extended Le with 6700.
	 */

	private static class SimulatedCard implements Mts7Exchange {

		private final byte[] selectApplicationResponse;
		private final boolean extendedLength;
		private final int maximumResponseLength;

		private final List<byte[]> commands = new ArrayList<>();

		private int mtbOffset = 0;

		public SimulatedCard(byte[] selectApplicationResponse, boolean extendedLength, int maximumResponseLength) {
			this.selectApplicationResponse = selectApplicationResponse;
			this.extendedLength = extendedLength;
			this.maximumResponseLength = maximumResponseLength;
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
			int length = Math.min(Math.min(maximumResponseLength, getNe(command)), MTB.length - mtbOffset);
			int remaining = MTB.length - mtbOffset - length;

			byte[] response = new byte[length + 2];
			System.arraycopy(MTB, mtbOffset, response, 0, length);
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

		public boolean hasExtendedLengthCommands() {
			for (byte[] command : commands) {
				if (isExtendedLength(command)) {
					return true;
				}
			}
			return false;
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
	 * Read the card with both the plain and the processor based reader, and check that the MTB is read in full.
	 *
	 * @return the cards which were read
	 */

	private List<SimulatedCard> readWithBoth(byte[] selectApplicationResponse, boolean extendedLength, int maximumResponseLength) throws Exception {
		List<SimulatedCard> cards = new ArrayList<>();

		SimulatedCard card = new SimulatedCard(selectApplicationResponse, extendedLength, maximumResponseLength);
		assertArrayEquals(MTB, new Mts7ApduPayloadsFactory().createCard(read(card)).getGetDataOutput());
		cards.add(card);

		SimulatedCard processorCard = new SimulatedCard(selectApplicationResponse, extendedLength, maximumResponseLength);
		assertArrayEquals(MTB, new Mts7ApduPayloadsFactory().createCard(readWithProcessor(processorCard)).getGetDataOutput());
		cards.add(processorCard);

		return cards;
	}

	@Test
	public void testCardWithoutExtendedLengthSupport() throws Exception {
		// like the MTS7 reference applet in its default configuration
		for (SimulatedCard card : readWithBoth(selectApplicationResponse(0x100, 0x100), false, 256)) {
			assertFalse(card.hasExtendedLengthCommands());

			// the MTB is 258 bytes, so it does not fit in one short response: select, get next data, get response, internal authenticate
			assertEquals(4, card.getCommands().size());
		}
	}

	@Test
	public void testCardWithoutExtendedLengthSupportUsingResponseChaining() throws Exception {
		for (SimulatedCard card : readWithBoth(selectApplicationResponse(0x100, 0x100), false, 100)) {
			assertFalse(card.hasExtendedLengthCommands());

			// select, get next data, two get responses, internal authenticate
			assertEquals(5, card.getCommands().size());
		}
	}

	@Test
	public void testCardWithMaximumShortLengths() throws Exception {
		// the maximum lengths of short APDUs do not indicate extended length support, even if the card accepts an extended Le
		for (SimulatedCard card : readWithBoth(selectApplicationResponse(0x105, 0x102), true, 256)) {
			assertFalse(card.hasExtendedLengthCommands());
			assertEquals(4, card.getCommands().size());
		}
	}

	@Test
	public void testCardWithExtendedLengthSupport() throws Exception {
		for (SimulatedCard card : readWithBoth(selectApplicationResponse(0x405, 0x402), true, 0x400)) {
			assertTrue(card.hasExtendedLengthCommands());

			// the whole MTB in a single response: select, get next data, internal authenticate
			assertEquals(3, card.getCommands().size());
		}
	}

	@Test
	public void testCardWithExtendedLengthSupportUsingResponseChaining() throws Exception {
		// room for one byte more than a short response, so that the MTB is just too long
		for (SimulatedCard card : readWithBoth(selectApplicationResponse(0x105, 0x103), true, 257)) {
			assertTrue(card.hasExtendedLengthCommands());

			// select, get next data, get response, internal authenticate
			assertEquals(4, card.getCommands().size());
			assertTrue(isExtendedLength(card.getCommands().get(2)), "get response with extended length");
		}
	}

	@Test
	public void testCardWithoutExtendedLengthInformation() throws Exception {
		// a terminal MUST accept an empty response to SELECT (MTS7 section 4.1.1)
		for (SimulatedCard card : readWithBoth(new byte[] { (byte) 0x90, 0x00 }, false, 256)) {
			assertFalse(card.hasExtendedLengthCommands());
		}
	}

	@Test
	public void testMaximumResponseApduLength() {
		assertEquals(0x100, Mts7ApduExchangesFactory.getMaximumResponseApduLength(selectApplicationResponse(0x100, 0x100)));
		assertEquals(0x102, Mts7ApduExchangesFactory.getMaximumResponseApduLength(selectApplicationResponse(0x105, 0x102)));
		assertEquals(0x402, Mts7ApduExchangesFactory.getMaximumResponseApduLength(selectApplicationResponse(0x405, 0x402)));

		assertFalse(Mts7ApduExchangesFactory.isExtendedLengthSupported(selectApplicationResponse(0x100, 0x100)));
		assertFalse(Mts7ApduExchangesFactory.isExtendedLengthSupported(selectApplicationResponse(0x105, 0x102)));
		assertTrue(Mts7ApduExchangesFactory.isExtendedLengthSupported(selectApplicationResponse(0x105, 0x103)));
	}

	@Test
	public void testMaximumResponseApduLengthNotIndicated() {
		assertEquals(-1, Mts7ApduExchangesFactory.getMaximumResponseApduLength(null));
		assertEquals(-1, Mts7ApduExchangesFactory.getMaximumResponseApduLength(new byte[] { (byte) 0x90, 0x00 }));

		// without the Extended Length Information
		assertEquals(-1, Mts7ApduExchangesFactory.getMaximumResponseApduLength(
				ByteArrayHexStringConverter.hexStringToByteArray("641E6E1C4F10A0000007810101000A0000175F96B61D7A0593030000248A01009000")));

		// with only the maximum command APDU length
		assertEquals(-1, Mts7ApduExchangesFactory.getMaximumResponseApduLength(
				ByteArrayHexStringConverter.hexStringToByteArray("64256E234F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660402020105" + "9000")));

		// truncated: the maximum response APDU length has no value
		assertFalse(Mts7ApduExchangesFactory
				.isExtendedLengthSupported(ByteArrayHexStringConverter.hexStringToByteArray(SELECT_APPLICATION_RESPONSE_PREFIX + "04050202" + "9000")));
	}

}
