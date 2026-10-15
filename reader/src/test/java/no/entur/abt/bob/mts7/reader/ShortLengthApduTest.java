package no.entur.abt.bob.mts7.reader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

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
 * Support for extended length APDUs is optional for the PICC (MTS7 section 3.1.4), and a PICC which does not support it rejects an extended Le with 6700
 * (wrong length). The reader must therefore use short APDUs, and rely on response chaining (MTS7 section 2.1) for longer responses.
 */

public class ShortLengthApduTest extends AbstractExecutorTest {

	// Extended Length Information (7F66) with maximum command and response APDU lengths of 256 bytes, i.e. no extended length support
	private static final byte[] SELECT_APPLICATION_RESPONSE = ByteArrayHexStringConverter
			.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020100020201009000");

	// genuine MTB (without the status words)
	private static final byte[] MTB = ByteArrayHexStringConverter.hexStringToByteArray(
			"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C4603");

	private static final byte[] SIGNATURE_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");

	private static final byte[] WRONG_LENGTH = { 0x67, 0x00 };

	/**
	 * A card which does not support extended length APDUs: it rejects a command with an extended Le with 6700, and returns at most <code>maxResponse</code>
	 * bytes of the MTB in each response, the rest using response chaining (61xx and GET RESPONSE).
	 */

	private static class ShortLengthCard implements Mts7Exchange {

		private final int maxResponse;
		private final List<byte[]> commands = new ArrayList<>();

		private int mtbOffset = 0;

		public ShortLengthCard(int maxResponse) {
			this.maxResponse = maxResponse;
		}

		@Override
		public byte[] getTagId() {
			return null;
		}

		@Override
		public byte[] transceive(byte[] command) throws IOException {
			commands.add(command);

			if (isExtendedLength(command)) {
				return WRONG_LENGTH;
			}

			int ins = command[1] & 0xFF;
			switch (ins) {
			case 0xA4: // select application
				return SELECT_APPLICATION_RESPONSE;
			case 0xCC: // get next data
				mtbOffset = 0;
				return nextMtbPart();
			case 0xC0: // get response
				return nextMtbPart();
			case 0x88: // internal authenticate
				return SIGNATURE_RESPONSE;
			default:
				throw new IOException("Unexpected command " + ByteArrayHexStringConverter.toHexString(command));
			}
		}

		/**
		 * An extended length APDU has a zero byte where a short APDU has its Lc or Le (ISO 7816-4 section 5.1), except for a short Le of 0x00 at the end of
		 * the command.
		 */

		private static boolean isExtendedLength(byte[] command) {
			return command.length > 5 && command[4] == 0x00;
		}

		private byte[] nextMtbPart() {
			int length = Math.min(maxResponse, MTB.length - mtbOffset);
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
	}

	private Random random() {
		return MockRandomFactory.newInstance(new byte[32]);
	}

	private Mts7ApduExchanges read(ShortLengthCard card) throws Exception {
		return new Mts7ApduExchangesFactory(random()).createCard(card, null);
	}

	private Mts7ApduExchanges readWithProcessor(ShortLengthCard card) throws Exception {
		Mts7Processor processor = new VerifyKeyPairMts7ProcessorFactory(executor).create();
		try {
			return new ProcessorMts7ApduExchangesFactory(random()).create(card, processor, null);
		} finally {
			processor.close();
		}
	}

	private void assertMtbRead(ShortLengthCard card, Mts7ApduExchanges exchanges) throws Exception {
		for (byte[] command : card.getCommands()) {
			assertFalse(ShortLengthCard.isExtendedLength(command), "Extended length command " + ByteArrayHexStringConverter.toHexString(command));
		}

		assertArrayEquals(MTB, new Mts7ApduPayloadsFactory().createCard(exchanges).getGetDataOutput());
	}

	@Test
	public void testCardWithoutExtendedLengthSupport() throws Exception {
		ShortLengthCard card = new ShortLengthCard(256);
		Mts7ApduExchanges exchanges = read(card);

		assertMtbRead(card, exchanges);

		// the MTB is 258 bytes, so it does not fit in one short response: select, get next data, get response, internal authenticate
		assertEquals(4, card.getCommands().size());
	}

	@Test
	public void testCardWithoutExtendedLengthSupportWithProcessor() throws Exception {
		ShortLengthCard card = new ShortLengthCard(256);

		assertMtbRead(card, readWithProcessor(card));
	}

	@Test
	public void testCardWithoutExtendedLengthSupportUsingResponseChaining() throws Exception {
		// MTB split in three parts
		ShortLengthCard card = new ShortLengthCard(100);
		Mts7ApduExchanges exchanges = read(card);

		assertMtbRead(card, exchanges);

		// select, get next data, two get responses, internal authenticate
		assertEquals(5, card.getCommands().size());
	}

	@Test
	public void testCardWithoutExtendedLengthSupportUsingResponseChainingWithProcessor() throws Exception {
		ShortLengthCard card = new ShortLengthCard(100);

		assertMtbRead(card, readWithProcessor(card));
	}

}
