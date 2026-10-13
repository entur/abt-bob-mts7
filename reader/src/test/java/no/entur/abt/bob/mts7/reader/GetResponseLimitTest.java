package no.entur.abt.bob.mts7.reader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Random;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.api.UnexpectedCardResponseException;
import no.entur.abt.bob.mts7.reader.processor.Mts7Processor;
import no.entur.abt.bob.mts7.reader.processor.VerifyKeyPairMts7ProcessorFactory;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchanges;
import no.entur.abt.bob.mts7.simple.reader.Mts7ApduExchangesFactory;
import no.entur.abt.bob.mts7.simple.reader.Mts7Exchange;
import no.entur.abt.bob.mts7.test.util.MockRandomFactory;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * A card which keeps saying that there is more data (61xx) must not keep the reader busy forever.
 */

public class GetResponseLimitTest {

	private static final byte[] SELECT_APPLICATION_RESPONSE = ByteArrayHexStringConverter
			.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");
	private static final byte[] SIGNATURE_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");

	private static final byte[] MORE_DATA = { 1, 2, 3, 0x61, 0x00 };
	private static final byte[] LAST_DATA = { 4, 5, 6, (byte) 0x90, 0x00 };

	// if the reader has not given up by then, it is never going to; do not hang the test
	private static final int GIVE_UP_AFTER = 10_000;

	/**
	 * A card which, after select application and get next data, answers get response with <code>more</code> parts with more data, and then with the last part.
	 */

	private static class MoreDataCard implements Mts7Exchange {

		private final int more;
		private int commands = 0;
		private int getResponses = 0;

		public MoreDataCard(int more) {
			this.more = more;
		}

		@Override
		public byte[] getTagId() {
			return null;
		}

		@Override
		public byte[] transceive(byte[] command) throws IOException {
			commands++;
			if (commands > GIVE_UP_AFTER) {
				throw new IOException("The reader did not give up");
			}

			int ins = command[1] & 0xFF;
			switch (ins) {
			case 0xA4: // select application
				return SELECT_APPLICATION_RESPONSE;
			case 0xCC: // get next data
				return MORE_DATA;
			case 0xC0: // get response
				getResponses++;
				return getResponses <= more ? MORE_DATA : LAST_DATA;
			case 0x88: // internal authenticate
				return SIGNATURE_RESPONSE;
			default:
				throw new IOException("Unexpected command " + ByteArrayHexStringConverter.toHexString(command));
			}
		}

		public int getGetResponses() {
			return getResponses;
		}
	}

	private Random random() {
		return MockRandomFactory.newInstance(new byte[32]);
	}

	private Mts7ApduExchanges read(MoreDataCard card) throws Exception {
		return new Mts7ApduExchangesFactory(random()).createCard(card, null);
	}

	private Mts7ApduExchanges readWithProcessor(MoreDataCard card) throws Exception {
		Mts7Processor processor = new VerifyKeyPairMts7ProcessorFactory().create();

		return new ProcessorMts7ApduExchangesFactory(random()).create(card, processor, null);
	}

	@Test
	public void testCardWhichNeverStopsSayingThereIsMoreData() {
		MoreDataCard card = new MoreDataCard(Integer.MAX_VALUE);

		UnexpectedCardResponseException e = assertThrows(UnexpectedCardResponseException.class, () -> read(card));

		assertEquals(0xC0, e.getCommand()[1] & 0xFF);
		assertTrue(card.getGetResponses() < 1000, "get response sent " + card.getGetResponses() + " times");
	}

	@Test
	public void testCardWhichNeverStopsSayingThereIsMoreDataWithProcessor() {
		MoreDataCard card = new MoreDataCard(Integer.MAX_VALUE);

		UnexpectedCardResponseException e = assertThrows(UnexpectedCardResponseException.class, () -> readWithProcessor(card));

		assertEquals(0xC0, e.getCommand()[1] & 0xFF);
		assertTrue(card.getGetResponses() < 1000, "get response sent " + card.getGetResponses() + " times");
	}

	@Test
	public void testLongResponseIsAccepted() throws Exception {
		// a lot more than a real card needs, but a legitimate card all the same
		int more = 100;

		MoreDataCard card = new MoreDataCard(more);
		Mts7ApduExchanges exchanges = read(card);
		// select, get next data, get responses (more + the last), internal authenticate
		assertEquals(2 + more + 1 + 1, exchanges.getExchanges().size());

		MoreDataCard processorCard = new MoreDataCard(more);
		assertEquals(2 + more + 1 + 1, readWithProcessor(processorCard).getExchanges().size());
	}

	@Test
	public void testSplitResponseIsAccepted() throws Exception {
		assertEquals(5, read(new MoreDataCard(1)).getExchanges().size());
		assertEquals(5, readWithProcessor(new MoreDataCard(1)).getExchanges().size());
	}

}
