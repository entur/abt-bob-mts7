package no.entur.abt.bob.mts7.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

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
		// the card says there is more to get (61xx), but no get response follows
		UnexpectedCardResponseException e = assertThrows(UnexpectedCardResponseException.class,
				() -> factory.createCard(exchanges(SELECT_BOB_COMMAND, SELECT_APPLICATION_RESPONSE, GET_NEXT_DATA_COMMAND, firstPart(), GET_NEXT_DATA_COMMAND,
						GET_DATA_RESPONSE, INTERNAL_AUTHENTICATE_COMMAND, SIGNATURE_RESPONSE)));

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

	public byte[] fromResponseApdu(byte[] response) {
		byte[] payload = new byte[response.length - 2];
		System.arraycopy(response, 0, payload, 0, payload.length);
		return payload;
	}
}
