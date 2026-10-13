package no.entur.abt.bob.mts7.reader.processor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.Random;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.reader.ProcessorMts7ApduExchangesFactory;
import no.entur.abt.bob.mts7.simple.reader.Mts7Exchange;
import no.entur.abt.bob.mts7.test.util.MockRandomFactory;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * The payloads (i.e. without the status bytes) which the processors get for the response APDUs.
 */

public class Mts7ProcessorTest {

	private static final byte[] SELECT_APPLICATION_RESPONSE = ByteArrayHexStringConverter
			.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");
	private static final byte[] GET_NEXT_DATA_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000");
	private static final byte[] SIGNATURE_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");

	private static byte[] withoutStatus(byte[] response) {
		return Arrays.copyOf(response, response.length - 2);
	}

	/**
	 * Processor which remembers what it was given.
	 */

	private static class RecordingProcessor implements Mts7Processor {

		byte[] selectApplication;
		byte[] getData;
		byte[] internalAuthenticateCommand;
		byte[] internalAuthenticateResponse;

		@Override
		public void run() {
		}

		@Override
		public void start() {
		}

		@Override
		public void close() {
		}

		@Override
		public String waitForAlgorithm(long delay) {
			return null;
		}

		@Override
		public Mts7Card waitForVerify(long timeout) {
			return null;
		}

		@Override
		public void onGetData(byte[] responsePayload) {
			this.getData = responsePayload;
		}

		@Override
		public void onInternalAuthenticate(byte[] commandPayload, byte[] responsePayload) {
			this.internalAuthenticateCommand = commandPayload;
			this.internalAuthenticateResponse = responsePayload;
		}

		@Override
		public void onSelectApplication(byte[] responsePayload) {
			this.selectApplication = responsePayload;
		}
	}

	@Test
	public void testSelectApplicationResponseApdu() {
		RecordingProcessor processor = new RecordingProcessor();

		processor.onSelectApplicationResponseApdu(SELECT_APPLICATION_RESPONSE);

		assertArrayEquals(withoutStatus(SELECT_APPLICATION_RESPONSE), processor.selectApplication);
	}

	@Test
	public void testGetDataResponseApdu() {
		RecordingProcessor processor = new RecordingProcessor();

		processor.onGetDataResponseApdu(GET_NEXT_DATA_RESPONSE);

		assertArrayEquals(withoutStatus(GET_NEXT_DATA_RESPONSE), processor.getData);
	}

	@Test
	public void testInternalAuthenticateApdu() {
		RecordingProcessor processor = new RecordingProcessor();

		byte[] challenge = new byte[32];
		Arrays.fill(challenge, (byte) 7);

		byte[] command = new byte[5 + 32 + 1];
		command[1] = (byte) 0x88;
		command[4] = 0x20;
		System.arraycopy(challenge, 0, command, 5, 32);

		processor.onInternalAuthenticateApdu(command, SIGNATURE_RESPONSE);

		assertArrayEquals(challenge, processor.internalAuthenticateCommand);
		assertArrayEquals(withoutStatus(SIGNATURE_RESPONSE), processor.internalAuthenticateResponse);
	}

	@Test
	public void testPayloadsFromTheReader() throws Exception {
		// what the processors get when the reader reads a card
		RecordingProcessor processor = new RecordingProcessor();

		Mts7Exchange card = new Mts7Exchange() {

			private int count = 0;

			@Override
			public byte[] getTagId() {
				return null;
			}

			@Override
			public byte[] transceive(byte[] command) {
				byte[][] responses = { SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_RESPONSE, SIGNATURE_RESPONSE };
				return responses[count++];
			}
		};

		Random random = MockRandomFactory.newInstance(new byte[32]);

		new ProcessorMts7ApduExchangesFactory(random).create(card, processor, null);

		assertEquals(SELECT_APPLICATION_RESPONSE.length - 2, processor.selectApplication.length);
		assertArrayEquals(withoutStatus(SELECT_APPLICATION_RESPONSE), processor.selectApplication);
		assertArrayEquals(withoutStatus(GET_NEXT_DATA_RESPONSE), processor.getData);
		assertArrayEquals(withoutStatus(SIGNATURE_RESPONSE), processor.internalAuthenticateResponse);
	}

}
