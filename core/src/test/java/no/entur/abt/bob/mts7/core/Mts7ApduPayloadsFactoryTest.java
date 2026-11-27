package no.entur.abt.bob.mts7.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.api.InsufficientCardCommandsException;
import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.api.MalformedCardResponseException;
import no.entur.abt.bob.mts7.api.Mts7Exception;
import no.entur.abt.bob.mts7.api.UnexpectedCardResponseException;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchanges;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class Mts7ApduPayloadsFactoryTest {

	public static final byte[] SELECT_BOB_COMMAND = new byte[] { 0x00, (byte) 0xA4, 0x04, 0x00, 0x06, (byte) 0xA0, 0x00, 0x00, 0x07, (byte) 0x81, 0x01 };
	public static final byte[] GET_DATA_COMMAND = new byte[] { 0x00, (byte) 0xCA, 0x7F, 0x21, 0x00, 0x00, 0x00 };
	public static final byte[] GET_NEXT_DATA_COMMAND = new byte[] { 0x00, (byte) 0xCC, 0x7F, 0x21, 0x00, 0x00, 0x00 };
	public static final byte[] GET_RESPONSE_COMMAND = new byte[] { 0x00, (byte) 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00 };
	public static final byte[] INTERNAL_AUTHENTICATE_COMMAND_PREFIX = new byte[] { 0x00, (byte) 0x88, 0x00, 0x00, 0x20 };
	public static final byte[] INTERNAL_AUTHENTICATE_COMMAND_POSTFIX = new byte[] { 0x00 };

	private Mts7ApduPayloadsFactory factory = new Mts7ApduPayloadsFactory();

	@Test
	public void testParseSingleDataResponse() throws IOException, Mts7Exception {

		ByteArrayOutputStream bout = new ByteArrayOutputStream(128);
		bout.write(INTERNAL_AUTHENTICATE_COMMAND_PREFIX);
		byte[] challenge = ByteArrayHexStringConverter.hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000000");
		bout.write(challenge);
		bout.write(INTERNAL_AUTHENTICATE_COMMAND_POSTFIX);

		byte[] selectApplicationResponse = ByteArrayHexStringConverter
				.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");
		byte[] getNextDataResponse = ByteArrayHexStringConverter.hexStringToByteArray(
				"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000");
		byte[] signatureResponse = ByteArrayHexStringConverter.hexStringToByteArray(
				"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");

		Mts7ApduExchanges exchanges = new Mts7ApduExchanges();
		exchanges.add(SELECT_BOB_COMMAND, selectApplicationResponse);
		exchanges.add(GET_DATA_COMMAND, getNextDataResponse);
		exchanges.add(bout.toByteArray(), signatureResponse);

		Mts7ApduPayloads decoded = factory.createCard(exchanges);

		Mts7ApduPayloads binaryCard = new Mts7ApduPayloads();
		binaryCard.setSelectApplicationOutput(fromResponseApdu(selectApplicationResponse));
		binaryCard.setGetDataOutput(fromResponseApdu(getNextDataResponse));
		binaryCard.setInternalAuthenticateInput(challenge);
		binaryCard.setInternalAuthenticateOutput(fromResponseApdu(signatureResponse));

		assertEquals(decoded, binaryCard);
	}

	@Test
	public void testParseMultipleDataResponse() throws IOException, Mts7Exception {

		ByteArrayOutputStream bout = new ByteArrayOutputStream(128);
		bout.write(INTERNAL_AUTHENTICATE_COMMAND_PREFIX);
		byte[] challenge = ByteArrayHexStringConverter.hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000000");
		bout.write(challenge);
		bout.write(INTERNAL_AUTHENTICATE_COMMAND_POSTFIX);

		byte[] selectApplicationResponse = ByteArrayHexStringConverter
				.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");
		byte[] getNextDataResponse = ByteArrayHexStringConverter.hexStringToByteArray(
				"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000");
		byte[] signatureResponse = ByteArrayHexStringConverter.hexStringToByteArray(
				"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");

		Mts7ApduExchanges exchanges = new Mts7ApduExchanges();
		exchanges.add(SELECT_BOB_COMMAND, selectApplicationResponse);

		byte[] getNextDataPayload = fromResponseApdu(getNextDataResponse);

		int segments = 4;
		int segmentLength = getNextDataPayload.length / segments + getNextDataPayload.length % segments;

		int offset = 0;
		while (offset < getNextDataPayload.length) {

			int limit = Math.min(offset + segmentLength, getNextDataPayload.length);

			int length = limit - offset;

			byte[] payload = new byte[length + 2];
			System.arraycopy(getNextDataPayload, offset, payload, 0, length);

			boolean last = limit == getNextDataPayload.length;

			if (last) {
				payload[payload.length - 1] = 0x00;
				payload[payload.length - 2] = (byte) 0x90;
			} else {
				payload[payload.length - 1] = 0x00;
				payload[payload.length - 2] = (byte) 0x61;
			}

			if (offset == 0) {
				exchanges.add(GET_DATA_COMMAND, payload);
			} else {
				exchanges.add(GET_RESPONSE_COMMAND, payload);
			}

			offset += length;
		}

		exchanges.add(bout.toByteArray(), signatureResponse);

		assertEquals(6, exchanges.getExchanges().size());

		Mts7ApduPayloads decoded = factory.createCard(exchanges);

		Mts7ApduPayloads binaryCard = new Mts7ApduPayloads();
		binaryCard.setSelectApplicationOutput(fromResponseApdu(selectApplicationResponse));
		binaryCard.setGetDataOutput(fromResponseApdu(getNextDataResponse));
		binaryCard.setInternalAuthenticateInput(challenge);
		binaryCard.setInternalAuthenticateOutput(fromResponseApdu(signatureResponse));

		assertArrayEquals(decoded.getSelectApplicationOutput(), binaryCard.getSelectApplicationOutput());
		assertArrayEquals(decoded.getInternalAuthenticateInput(), binaryCard.getInternalAuthenticateInput());
		assertArrayEquals(decoded.getInternalAuthenticateOutput(), binaryCard.getInternalAuthenticateOutput());

		assertArrayEquals(decoded.getGetDataOutput(), binaryCard.getGetDataOutput());

		assertEquals(decoded, binaryCard);
	}

	private static final byte[] SELECT_APPLICATION_RESPONSE = ByteArrayHexStringConverter
			.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");
	private static final byte[] GET_DATA_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000");
	private static final byte[] SIGNATURE_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");

	private static final byte[] CHALLENGE = new byte[32];

	// internal authenticate command with an all-zeroes challenge
	private static final byte[] INTERNAL_AUTHENTICATE_COMMAND = ByteArrayHexStringConverter
			.hexStringToByteArray("0088000020" + "0000000000000000000000000000000000000000000000000000000000000000" + "00");

	private static final byte[] NOT_SATISFIED = { (byte) 0x69, (byte) 0x85 };
	private static final byte[] FILE_NOT_FOUND = { (byte) 0x6A, (byte) 0x82 };

	/**
	 * Create exchanges from alternating commands and responses
	 */

	private static Mts7ApduExchanges exchanges(byte[]... commandsAndResponses) {
		Mts7ApduExchanges exchanges = new Mts7ApduExchanges();
		for (int i = 0; i < commandsAndResponses.length; i += 2) {
			exchanges.add(commandsAndResponses[i], commandsAndResponses[i + 1]);
		}
		return exchanges;
	}

	// the get data response split in two, i.e. the first part says that there is more (61xx), the second is the rest

	private byte[] firstPart() {
		byte[] payload = fromResponseApdu(GET_DATA_RESPONSE);
		byte[] result = Arrays.copyOf(payload, payload.length / 2 + 2);
		result[result.length - 2] = 0x61;
		result[result.length - 1] = 0x00;
		return result;
	}

	private byte[] secondPart() {
		byte[] payload = fromResponseApdu(GET_DATA_RESPONSE);
		int split = payload.length / 2;
		byte[] result = new byte[payload.length - split + 2];
		System.arraycopy(payload, split, result, 0, payload.length - split);
		result[result.length - 2] = (byte) 0x90;
		result[result.length - 1] = 0x00;
		return result;
	}

	private Mts7ApduPayloads expectedPayloads() {
		Mts7ApduPayloads payloads = new Mts7ApduPayloads();
		payloads.setSelectApplicationOutput(fromResponseApdu(SELECT_APPLICATION_RESPONSE));
		payloads.setGetDataOutput(fromResponseApdu(GET_DATA_RESPONSE));
		payloads.setInternalAuthenticateInput(CHALLENGE);
		payloads.setInternalAuthenticateOutput(fromResponseApdu(SIGNATURE_RESPONSE));
		return payloads;
	}

	@Test
	public void testSplitResponseSanity() throws Exception {
		// guard the helpers used below
		Mts7ApduPayloads decoded = factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, firstPart(),
				GET_RESPONSE_COMMAND, secondPart(), INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE));

		assertEquals(expectedPayloads(), decoded);
	}

	@Test
	public void testIgnoreUnsuccessfulInternalAuthenticateAfterGetData() throws Exception {
		Mts7ApduPayloads decoded = factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE,
				INTERNAL_AUTHENTICATE_COMMAND, NOT_SATISFIED, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE));

		assertEquals(expectedPayloads(), decoded);
	}

	@Test
	public void testIgnoreUnsuccessfulInternalAuthenticateBeforeGetData() throws Exception {
		Mts7ApduPayloads decoded = factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, NOT_SATISFIED,
				GET_NEXT_DATA_COMMAND, firstPart(), GET_RESPONSE_COMMAND, secondPart(), INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE));

		assertEquals(expectedPayloads(), decoded);
	}

	@Test
	public void testUnsuccessfulInternalAuthenticateIsNotGetData() {
		// nothing but an unsuccessful internal authenticate between select application and the final internal authenticate
		assertThrows(MissingCardCommandsException.class, () -> factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE,
				INTERNAL_AUTHENTICATE_COMMAND, NOT_SATISFIED, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
	}

	@Test
	public void testFailedGetResponseIsRejected() {
		UnexpectedCardResponseException e = assertThrows(UnexpectedCardResponseException.class,
				() -> factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, firstPart(), GET_RESPONSE_COMMAND,
						FILE_NOT_FOUND, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));

		assertArrayEquals(GET_RESPONSE_COMMAND, e.getCommand());
		assertArrayEquals(FILE_NOT_FOUND, e.getResponse());
	}

	@Test
	public void testFailedGetResponseIsRejectedWhenFollowedByAnotherGetNextData() {
		// whether the failure is detected must not depend on what happens to follow the failed response
		UnexpectedCardResponseException e = assertThrows(UnexpectedCardResponseException.class,
				() -> factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, firstPart(), GET_RESPONSE_COMMAND,
						FILE_NOT_FOUND, GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));

		assertArrayEquals(GET_RESPONSE_COMMAND, e.getCommand());
		assertArrayEquals(FILE_NOT_FOUND, e.getResponse());
	}

	@Test
	public void testIncompleteResponseIsRejected() {
		// the card says there is more to get (61xx), but no get response follows: the reader did not retrieve it (MTS7, section 4.1.3)
		InsufficientCardCommandsException e = assertThrows(InsufficientCardCommandsException.class,
				() -> factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, firstPart(), GET_NEXT_DATA_COMMAND,
						GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));

		assertArrayEquals(GET_NEXT_DATA_COMMAND, e.getCommand());
		assertArrayEquals(firstPart(), e.getResponse());
	}

	@Test
	public void testIncompleteResponseBeforeInternalAuthenticateIsReaderProblem() {
		// the card says there is more to get (61xx), but the reader goes on to internal authenticate
		InsufficientCardCommandsException e = assertThrows(InsufficientCardCommandsException.class, () -> factory.createCard(exchanges(SELECT_BOB_COMMAND,
				SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, firstPart(), INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));

		assertArrayEquals(GET_NEXT_DATA_COMMAND, e.getCommand());
		assertArrayEquals(firstPart(), e.getResponse());
	}

	@Test
	public void testFailedGetResponseInTheMiddleIsRejected() {
		// do not silently drop the data from a get response which failed
		UnexpectedCardResponseException e = assertThrows(UnexpectedCardResponseException.class,
				() -> factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, firstPart(), GET_RESPONSE_COMMAND,
						FILE_NOT_FOUND, GET_RESPONSE_COMMAND, secondPart(), INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));

		assertArrayEquals(FILE_NOT_FOUND, e.getResponse());
	}

	@Test
	public void testGetResponseAfterCompleteResponseIsRejected() {
		// get response is only valid when the previous response said there was more (61xx); do not append it to a complete response
		UnexpectedCardCommandException e = assertThrows(UnexpectedCardCommandException.class,
				() -> factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE,
						GET_RESPONSE_COMMAND, secondPart(), INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));

		assertArrayEquals(GET_RESPONSE_COMMAND, e.getCommand());
	}

	// exchanges which cannot be from a card are a problem with the reader, never a RuntimeException

	@Test
	public void testMissingExchangesAreReaderProblem() {
		assertThrows(MissingCardCommandsException.class, () -> factory.createCard(null));
		assertThrows(MissingCardCommandsException.class, () -> factory.createCard(new Mts7ApduExchanges()));
	}

	@Test
	public void testShortCommandIsReaderProblem() {
		for (byte[] command : new byte[][] { null, {}, { 0x00, (byte) 0xCA, 0x7F } }) {
			MalformedCardCommandException e = assertThrows(MalformedCardCommandException.class, () -> factory.createCard(
					exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, command, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
			assertTrue(e.getMessage().startsWith("Malformed command"), e.getMessage());
		}
	}

	@Test
	public void testShortResponseIsReaderProblem() {
		for (byte[] response : new byte[][] { null, {}, { (byte) 0x90 } }) {
			MalformedCardResponseException e = assertThrows(MalformedCardResponseException.class, () -> factory.createCard(
					exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_DATA_COMMAND, response, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
			assertTrue(e.getMessage().startsWith("Malformed response"), e.getMessage());
		}
	}

	@Test
	public void testMissingExchangeIsReaderProblem() {
		Mts7ApduExchanges exchanges = exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_DATA_COMMAND, GET_DATA_RESPONSE,
				INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE);
		exchanges.getExchanges().add(1, null);

		assertThrows(MissingCardCommandsException.class, () -> factory.createCard(exchanges));
	}

	@Test
	public void testMalformedInternalAuthenticateIsReaderProblem() {
		// says 32 bytes of data, but has 3
		byte[] command = ByteArrayHexStringConverter.hexStringToByteArray("0088000020" + "000000");

		MalformedCardCommandException e = assertThrows(MalformedCardCommandException.class, () -> factory
				.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_DATA_COMMAND, GET_DATA_RESPONSE, command, SIGNATURE_RESPONSE)));
		assertEquals("Malformed command", e.getMessage());
	}

	@Test
	public void testChallengeWhichIsNotASha256HashIsReaderProblem() {
		// the challenge SHALL be a SHA-256 hash, i.e. 32 bytes (MTS7, section 4.1.4)
		for (int length : new int[] { 0, 16, 31, 33, 64 }) {
			StringBuilder hex = new StringBuilder("00880000");
			if (length > 0) {
				hex.append(String.format("%02X", length));
				for (int i = 0; i < length; i++) {
					hex.append("00");
				}
			}
			hex.append("00");
			byte[] command = ByteArrayHexStringConverter.hexStringToByteArray(hex.toString());

			MalformedCardCommandException e = assertThrows(MalformedCardCommandException.class,
					() -> factory.createCard(
							exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_DATA_COMMAND, GET_DATA_RESPONSE, command, SIGNATURE_RESPONSE)),
					"" + length);
			assertEquals("Challenge for internal authenticate of " + length + " bytes, not 32", e.getMessage());
		}
	}

	@Test
	public void testChallengeIsCheckedBeforeTheResponse() {
		// the card rejects a challenge of the wrong length (wrong length), but that is the fault of the reader
		byte[] command = ByteArrayHexStringConverter.hexStringToByteArray("0088000010" + "00000000000000000000000000000000" + "00");
		byte[] wrongLength = { 0x67, 0x00 };

		assertThrows(MalformedCardCommandException.class, () -> factory
				.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_DATA_COMMAND, GET_DATA_RESPONSE, command, wrongLength)));
	}

	@Test
	public void testUnexpectedResponseIsCardProblem() {
		// the card does not have the application
		InvalidCardMts7Exception e = assertThrows(InvalidCardMts7Exception.class, () -> factory.createCard(
				exchanges(SELECT_BOB_COMMAND, FILE_NOT_FOUND, GET_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
		assertInstanceOf(UnexpectedCardResponseException.class, e);
		assertEquals("Unexpected response from the card: status word 6A82", e.getMessage());
	}

	// every command is checked before the response of the card, as the card can only answer the command it got

	@Test
	public void testSelectOfAnotherApplicationIsReaderProblem() {
		byte[] selectOther = ByteArrayHexStringConverter.hexStringToByteArray("00A4040007A0000000041010");

		assertThrows(UnexpectedCardCommandException.class, () -> factory
				.createCard(exchanges(selectOther, FILE_NOT_FOUND, GET_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
	}

	@Test
	public void testSelectOfTheFullApplicationIdentifier() throws Exception {
		// it starts with the part which MTS7 selects
		byte[] select = ByteArrayHexStringConverter.hexStringToByteArray("00A4040010A0000007810101000A0000175F96B61D00");

		assertNotNull(factory.createCard(
				exchanges(select, SELECT_APPLICATION_RESPONSE, GET_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
	}

	@Test
	public void testInternalAuthenticateWithoutLeIsReaderProblem() {
		// the card would rightly not return the signature
		byte[] command = ByteArrayHexStringConverter.hexStringToByteArray("0088000020" + "00".repeat(32));

		MalformedCardCommandException e = assertThrows(MalformedCardCommandException.class, () -> factory.createCard(
				exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_DATA_COMMAND, GET_DATA_RESPONSE, command, new byte[] { (byte) 0x90, 0x00 })));
		assertTrue(e.getMessage().contains("without Le"), e.getMessage());
	}

	@Test
	public void testGetCommandsWithoutLeOrWithDataAreReaderProblem() {
		byte[] getDataWithoutLe = ByteArrayHexStringConverter.hexStringToByteArray("00CA7F21");
		byte[] getDataWithData = ByteArrayHexStringConverter.hexStringToByteArray("00CA7F210101");
		byte[] getResponseWithoutLe = ByteArrayHexStringConverter.hexStringToByteArray("00C00000");

		assertThrows(MalformedCardCommandException.class, () -> factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, getDataWithoutLe,
				new byte[] { (byte) 0x90, 0x00 }, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
		assertThrows(MalformedCardCommandException.class, () -> factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, getDataWithData,
				GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
		assertThrows(MalformedCardCommandException.class, () -> factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE,
				GET_NEXT_DATA_COMMAND, firstPart(), getResponseWithoutLe, secondPart(), INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
	}

	@Test
	public void testContinueWithoutDataIsMore() throws Exception {
		// 61xx means that there is more, also with no data in this part of the response
		Mts7ApduPayloads payloads = factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND,
				new byte[] { 0x61, 0x00 }, GET_RESPONSE_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE));

		assertArrayEquals(fromResponseApdu(GET_DATA_RESPONSE), payloads.getGetDataOutput());
	}

	@Test
	public void testNoNextMobileTicketBundle() throws Exception {
		// a reader which looks for more than the first MTB gets referenced data not found (MTS7 section 4.1.2)
		byte[] notFound = { 0x6A, (byte) 0x88 };
		Mts7ApduPayloads payloads = factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE,
				GET_NEXT_DATA_COMMAND, notFound, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE));

		assertArrayEquals(fromResponseApdu(GET_DATA_RESPONSE), payloads.getGetDataOutput());
	}

	@Test
	public void testNoMobileTicketBundleIsCardProblem() {
		// the card MUST have at least one MTB (MTS7 section 3.1.5)
		byte[] notFound = { 0x6A, (byte) 0x88 };

		assertThrows(UnexpectedCardResponseException.class, () -> factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE,
				GET_NEXT_DATA_COMMAND, notFound, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
	}

	@Test
	public void testFirstMobileTicketBundleIsKept() throws Exception {
		// the card is authenticated with the public key of the first MTB (MTS7 appendix A)
		byte[] other = ByteArrayHexStringConverter.hexStringToByteArray("A09000");
		Mts7ApduPayloads payloads = factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE,
				GET_NEXT_DATA_COMMAND, other, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE));

		assertArrayEquals(fromResponseApdu(GET_DATA_RESPONSE), payloads.getGetDataOutput());
	}

	@Test
	public void testApplicationRelatedDataFromGetData() throws Exception {
		// the card need not return it in the select application response (MTS7 section 4.1.1)
		byte[] getApplicationRelatedData = ByteArrayHexStringConverter.hexStringToByteArray("00CA006E00");
		byte[] applicationRelatedData = ByteArrayHexStringConverter
				.hexStringToByteArray("6E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");

		Mts7ApduPayloads payloads = factory.createCard(exchanges(SELECT_BOB_COMMAND, new byte[] { (byte) 0x90, 0x00 }, getApplicationRelatedData,
				applicationRelatedData, GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE));

		assertEquals(0, payloads.getSelectApplicationOutput().length);
		assertArrayEquals(fromResponseApdu(applicationRelatedData), payloads.getApplicationRelatedDataOutput());
		assertArrayEquals(fromResponseApdu(GET_DATA_RESPONSE), payloads.getGetDataOutput());

		// which the card must have
		assertThrows(UnexpectedCardResponseException.class,
				() -> factory.createCard(exchanges(SELECT_BOB_COMMAND, new byte[] { (byte) 0x90, 0x00 }, getApplicationRelatedData,
						new byte[] { 0x6A, (byte) 0x88 }, GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
	}

	// every response may come in parts (MTS7 section 2.1), and the card may ask for a command again with another Le

	/**
	 * Split a response in two: the first part says that there is more (61xx), the second is the rest
	 */

	private static byte[][] split(byte[] response, int length) {
		byte[] first = new byte[length + 2];
		System.arraycopy(response, 0, first, 0, length);
		first[length] = 0x61;
		first[length + 1] = (byte) (response.length - 2 - length);
		return new byte[][] { first, Arrays.copyOfRange(response, length, response.length) };
	}

	private static final byte[] GET_RESPONSE_SHORT_COMMAND = { 0x00, (byte) 0xC0, 0x00, 0x00, 0x00 };

	@Test
	public void testSelectApplicationResponseInParts() throws Exception {
		byte[][] parts = split(SELECT_APPLICATION_RESPONSE, 16);
		Mts7ApduPayloads payloads = factory.createCard(exchanges(SELECT_BOB_COMMAND, parts[0], GET_RESPONSE_SHORT_COMMAND, parts[1], GET_NEXT_DATA_COMMAND,
				GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE));

		assertEquals(expectedPayloads(), payloads);

		// the reader did not retrieve the rest
		InsufficientCardCommandsException e = assertThrows(InsufficientCardCommandsException.class, () -> factory.createCard(
				exchanges(SELECT_BOB_COMMAND, parts[0], GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
		assertArrayEquals(SELECT_BOB_COMMAND, e.getCommand());
	}

	@Test
	public void testInternalAuthenticateResponseInParts() throws Exception {
		byte[][] parts = split(SIGNATURE_RESPONSE, 32);
		Mts7ApduPayloads payloads = factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE,
				INTERNAL_AUTHENTICATE_COMMAND, parts[0], GET_RESPONSE_SHORT_COMMAND, parts[1]));

		assertEquals(expectedPayloads(), payloads);

		// the reader did not retrieve the rest
		InsufficientCardCommandsException e = assertThrows(InsufficientCardCommandsException.class, () -> factory.createCard(
				exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, parts[0])));
		assertArrayEquals(INTERNAL_AUTHENTICATE_COMMAND, e.getCommand());

		// the card fails to return the rest
		UnexpectedCardResponseException failed = assertThrows(UnexpectedCardResponseException.class,
				() -> factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE,
						INTERNAL_AUTHENTICATE_COMMAND, parts[0], GET_RESPONSE_SHORT_COMMAND, NOT_SATISFIED)));
		assertArrayEquals(GET_RESPONSE_SHORT_COMMAND, failed.getCommand());
	}

	@Test
	public void testWrongLengthToExtendedLengthIsSentAgain() throws Exception {
		// a card need not support extended length (MTS7 section 3.1.4)
		byte[] wrongLength = { 0x67, 0x00 };
		byte[][] parts = split(SIGNATURE_RESPONSE, 32);
		byte[] extendedInternalAuthenticate = ByteArrayHexStringConverter.hexStringToByteArray("00880000000020" + "00".repeat(32) + "0000");

		Mts7ApduPayloads payloads = factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, firstPart(),
				GET_RESPONSE_COMMAND, wrongLength, GET_RESPONSE_SHORT_COMMAND, secondPart(), extendedInternalAuthenticate, wrongLength,
				INTERNAL_AUTHENTICATE_COMMAND, parts[0], GET_RESPONSE_COMMAND, wrongLength, GET_RESPONSE_SHORT_COMMAND, parts[1]));
		assertEquals(expectedPayloads(), payloads);

		// not sent again
		InsufficientCardCommandsException e = assertThrows(InsufficientCardCommandsException.class, () -> factory.createCard(exchanges(SELECT_BOB_COMMAND,
				SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE, extendedInternalAuthenticate, wrongLength)));
		assertArrayEquals(extendedInternalAuthenticate, e.getCommand());
		assertThrows(InsufficientCardCommandsException.class, () -> factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE,
				GET_NEXT_DATA_COMMAND, firstPart(), GET_RESPONSE_COMMAND, wrongLength, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));

		// nor a short Le, as the examples of GET (NEXT) DATA and GET RESPONSE in MTS7 have an extended Le
		byte[] getNextDataShort = { 0x00, (byte) 0xCC, 0x7F, 0x21, 0x00 };
		assertEquals(expectedPayloads(), factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, getNextDataShort, wrongLength,
				getNextDataShort, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
		assertThrows(InsufficientCardCommandsException.class, () -> factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE,
				GET_NEXT_DATA_COMMAND, wrongLength, getNextDataShort, wrongLength, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
	}

	@Test
	public void testWrongLengthToTheLengthsOfTheExamplesIsCardProblem() {
		// select application with a short Le of 00 (MTS7 section 4.1.1) or without Le (appendix A), and internal authenticate with a short Le of 00 (section
		// 4.1.4)
		byte[] wrongLength = { 0x67, 0x00 };
		byte[] selectWithLe = ByteArrayHexStringConverter.hexStringToByteArray("00A4040006A00000078101" + "00");

		assertThrows(UnexpectedCardResponseException.class, () -> factory.createCard(
				exchanges(SELECT_BOB_COMMAND, wrongLength, GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
		assertThrows(UnexpectedCardResponseException.class, () -> factory
				.createCard(exchanges(selectWithLe, wrongLength, GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
		assertThrows(UnexpectedCardResponseException.class, () -> factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE,
				GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, wrongLength)));

		// but not with another Le
		byte[] selectWithOtherLe = ByteArrayHexStringConverter.hexStringToByteArray("00A4040006A00000078101" + "10");
		assertThrows(InsufficientCardCommandsException.class, () -> factory.createCard(
				exchanges(selectWithOtherLe, wrongLength, GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
	}

	@Test
	public void testWrongLeIsSentAgain() throws Exception {
		// the card asks for the exact Le (ISO/IEC 7816-4 section 5.6)
		int length = SIGNATURE_RESPONSE.length - 2;
		byte[] wrongLe = { 0x6C, (byte) length };
		byte[] exactLe = ByteArrayHexStringConverter.hexStringToByteArray("0088000020" + "00".repeat(32) + String.format("%02X", length));

		Mts7ApduPayloads payloads = factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE,
				INTERNAL_AUTHENTICATE_COMMAND, wrongLe, exactLe, SIGNATURE_RESPONSE));
		assertEquals(expectedPayloads(), payloads);

		// also to select application and get next data
		payloads = factory.createCard(exchanges(SELECT_BOB_COMMAND, new byte[] { 0x6C, 0x2B }, SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE,
				GET_NEXT_DATA_COMMAND, new byte[] { 0x6C, 0x00 }, GET_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE));
		assertEquals(expectedPayloads(), payloads);

		// not sent again
		InsufficientCardCommandsException e = assertThrows(InsufficientCardCommandsException.class, () -> factory.createCard(
				exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, wrongLe)));
		assertArrayEquals(wrongLe, e.getResponse());
		assertThrows(InsufficientCardCommandsException.class, () -> factory.createCard(exchanges(SELECT_BOB_COMMAND, new byte[] { 0x6C, 0x2B },
				GET_NEXT_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
	}

	@Test
	public void testRejectedSelectOfTheFullApplicationIdentifierIsReaderProblem() {
		// only the 6 bytes of the RID and the application are submitted (MTS7 section 4.1.1), and the card need not have an application by a longer name
		byte[] select = ByteArrayHexStringConverter.hexStringToByteArray("00A4040010A0000007810101000A0000175F96B61D00");

		MalformedCardCommandException e = assertThrows(MalformedCardCommandException.class, () -> factory
				.createCard(exchanges(select, FILE_NOT_FOUND, GET_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));
		assertTrue(e.getMessage().contains("16 bytes, not 6"), e.getMessage());
	}

	@Test
	public void testRejectedInternalAuthenticateWithShortLeIsReaderProblem() throws Exception {
		// an Le for less than an RSA signature, which the card may not be able to return its signature within
		byte[] shortLe = ByteArrayHexStringConverter.hexStringToByteArray("0088000020" + "00".repeat(32) + "40");

		MalformedCardCommandException e = assertThrows(MalformedCardCommandException.class, () -> factory
				.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_DATA_COMMAND, GET_DATA_RESPONSE, shortLe, NOT_SATISFIED)));
		assertTrue(e.getMessage().contains("Le for 64 bytes"), e.getMessage());

		// accepted by the card
		assertEquals(expectedPayloads(), factory
				.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_DATA_COMMAND, GET_DATA_RESPONSE, shortLe, SIGNATURE_RESPONSE)));

		// with an Le of 00, as in MTS7, the card is to blame
		assertThrows(UnexpectedCardResponseException.class, () -> factory.createCard(
				exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, NOT_SATISFIED)));

		// as with the Le which the card asked for
		assertThrows(UnexpectedCardResponseException.class, () -> factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE,
				GET_DATA_COMMAND, GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, new byte[] { 0x6C, 0x40 }, shortLe, NOT_SATISFIED)));
		// but not with another Le than the card asked for
		assertThrows(MalformedCardCommandException.class, () -> factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_DATA_COMMAND,
				GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, new byte[] { 0x6C, 0x48 }, shortLe, NOT_SATISFIED)));
	}

	public byte[] fromResponseApdu(byte[] response) {
		byte[] payload = new byte[response.length - 2];
		System.arraycopy(response, 0, payload, 0, payload.length);
		return payload;
	}
}
