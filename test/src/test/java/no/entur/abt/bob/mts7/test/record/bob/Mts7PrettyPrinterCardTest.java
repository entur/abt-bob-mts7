package no.entur.abt.bob.mts7.test.record.bob;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.test.ListResponseCard;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class Mts7PrettyPrinterCardTest {

	private static final byte[] SELECT = ByteArrayHexStringConverter.hexStringToByteArray("00A4040006A00000078101");
	private static final byte[] GET_NEXT_DATA = ByteArrayHexStringConverter.hexStringToByteArray("00CC7F21000000");
	private static final byte[] GET_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray("00C00000000000");
	private static final byte[] INTERNAL_AUTHENTICATE = ByteArrayHexStringConverter
			.hexStringToByteArray("0088000020" + "0000000000000000000000000000000000000000000000000000000000000000" + "00");

	private static final byte[] SELECT_RESPONSE = ByteArrayHexStringConverter
			.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");
	private static final byte[] GET_NEXT_DATA_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000");
	private static final byte[] AUTHENTICATE_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");

	private static byte[] firstPart() {
		int split = (GET_NEXT_DATA_RESPONSE.length - 2) / 2;

		byte[] result = Arrays.copyOf(GET_NEXT_DATA_RESPONSE, split + 2);
		result[split] = 0x61;
		result[split + 1] = 0x00;
		return result;
	}

	private static byte[] secondPart() {
		int split = (GET_NEXT_DATA_RESPONSE.length - 2) / 2;

		return Arrays.copyOfRange(GET_NEXT_DATA_RESPONSE, split, GET_NEXT_DATA_RESPONSE.length);
	}

	private Mts7PrettyPrinterCard newCard(ListResponseCard card, boolean silent) {
		return Mts7PrettyPrinterCard.newBuilder().withCard(card).withPrettyPrinter(Mts7TlvPrettyPrinter.getInstance()).withSilent(silent).build();
	}

	private void assertTransparent(boolean silent, byte[]... commandsAndResponses) throws Exception {
		ListResponseCard card = new ListResponseCard();
		for (int i = 1; i < commandsAndResponses.length; i += 2) {
			card.add(commandsAndResponses[i]);
		}

		Mts7PrettyPrinterCard printer = newCard(card, silent);
		for (int i = 0; i < commandsAndResponses.length; i += 2) {
			assertArrayEquals(commandsAndResponses[i + 1], printer.transceive(commandsAndResponses[i]));
		}
	}

	@Test
	public void testSingleResponse() throws Exception {
		assertTransparent(false, SELECT, SELECT_RESPONSE, GET_NEXT_DATA, GET_NEXT_DATA_RESPONSE, INTERNAL_AUTHENTICATE, AUTHENTICATE_RESPONSE);
	}

	@Test
	public void testSplitResponse() throws Exception {
		// the card says that there is more (61xx), and then get response is used for the rest
		assertTransparent(false, SELECT, SELECT_RESPONSE, GET_NEXT_DATA, firstPart(), GET_RESPONSE, secondPart(), INTERNAL_AUTHENTICATE, AUTHENTICATE_RESPONSE);
	}

	@Test
	public void testSplitResponseSilent() throws Exception {
		assertTransparent(true, SELECT, SELECT_RESPONSE, GET_NEXT_DATA, firstPart(), GET_RESPONSE, secondPart(), INTERNAL_AUTHENTICATE, AUTHENTICATE_RESPONSE);
	}

	@Test
	public void testNoNextData() throws Exception {
		assertTransparent(false, SELECT, SELECT_RESPONSE, GET_NEXT_DATA, new byte[] { 0x6A, (byte) 0x88 }, INTERNAL_AUTHENTICATE, AUTHENTICATE_RESPONSE);
	}

	@Test
	public void testReferenceNotFound() {
		// next instance of the data object does not exist: 6A 88
		assertTrue(Mts7PrettyPrinterCard.isReferenceNotFound(new byte[] { 0x6A, (byte) 0x88 }));
		assertTrue(Mts7PrettyPrinterCard.isReferenceNotFound(new byte[] { 0x01, 0x02, 0x6A, (byte) 0x88 }));
	}

	@Test
	public void testOtherStatusIsNotReferenceNotFound() {
		// only both of SW1 and SW2
		assertFalse(Mts7PrettyPrinterCard.isReferenceNotFound(new byte[] { 0x6A, (byte) 0x82 }));
		assertFalse(Mts7PrettyPrinterCard.isReferenceNotFound(new byte[] { 0x61, (byte) 0x88 }));
		assertFalse(Mts7PrettyPrinterCard.isReferenceNotFound(new byte[] { (byte) 0x90, 0x00 }));
		assertFalse(Mts7PrettyPrinterCard.isReferenceNotFound(new byte[] { 0x61, 0x00 }));
	}

	@Test
	public void testResponseTooShortIsNotReferenceNotFound() {
		assertFalse(Mts7PrettyPrinterCard.isReferenceNotFound(new byte[0]));
		assertFalse(Mts7PrettyPrinterCard.isReferenceNotFound(new byte[] { 0x6A }));
	}

}
