package no.entur.abt.bob.mts7.api.apdu;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.util.List;

import org.junit.jupiter.api.Test;

public class ResponseAPDUTest {

	private static byte[] payload(int length) {
		byte[] result = new byte[length];
		for (int i = 0; i < length; i++) {
			result[i] = (byte) (i + 1);
		}
		return result;
	}

	private static byte[] join(List<ResponseAPDU> responses) throws Exception {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		for (ResponseAPDU response : responses) {
			out.write(response.getData());
		}
		return out.toByteArray();
	}

	@Test
	public void testStatusConstantsAreUnsigned() {
		// the same as getSW1() and getSW2()
		assertEquals(0x90, ResponseAPDU.OK);
		assertEquals(0xAF, ResponseAPDU.ADDITIONAL_FRAME);
	}

	@Test
	public void testSplitPayload() throws Exception {
		// 17 is 10 bytes of payload per response
		byte[] payload = payload(25);

		List<ResponseAPDU> responses = ResponseAPDU.getResponses(payload, 17);

		assertEquals(3, responses.size());
		assertEquals(10, responses.get(0).getNr());
		assertEquals(10, responses.get(1).getNr());
		assertEquals(5, responses.get(2).getNr());
		assertArrayEquals(payload, join(responses));

		// more to come for all but the last
		for (int i = 0; i < 2; i++) {
			assertEquals(ResponseAPDU.OK, responses.get(i).getSW1());
			assertEquals(ResponseAPDU.ADDITIONAL_FRAME, responses.get(i).getSW2());
			assertTrue(responses.get(i).isContinue());
			assertFalse(responses.get(i).isSuccess());
		}
		assertEquals(ResponseAPDU.OK, responses.get(2).getSW1());
		assertEquals(0x00, responses.get(2).getSW2());
		assertTrue(responses.get(2).isSuccess());
		assertFalse(responses.get(2).isContinue());
	}

	@Test
	public void testPayloadWhichIsAMultipleOfTheLength() throws Exception {
		byte[] payload = payload(20);

		List<ResponseAPDU> responses = ResponseAPDU.getResponses(payload, 17);

		assertEquals(2, responses.size());
		assertTrue(responses.get(0).isContinue());
		assertTrue(responses.get(1).isSuccess());
		assertArrayEquals(payload, join(responses));
	}

	@Test
	public void testSingleResponse() throws Exception {
		byte[] payload = payload(10);

		List<ResponseAPDU> responses = ResponseAPDU.getResponses(payload, 100);

		assertEquals(1, responses.size());
		assertTrue(responses.get(0).isSuccess());
		assertArrayEquals(payload, responses.get(0).getData());
	}

	@Test
	public void testEmptyPayload() {
		// there is still a response, with only the status
		List<ResponseAPDU> responses = ResponseAPDU.getResponses(new byte[0], 100);

		assertEquals(1, responses.size());
		assertEquals(0, responses.get(0).getNr());
		assertTrue(responses.get(0).isSuccess());
		assertArrayEquals(new byte[] { (byte) 0x90, 0x00 }, responses.get(0).getBytes());
	}

	@Test
	public void testShortestResponses() throws Exception {
		// one byte of payload per response
		byte[] payload = payload(3);

		List<ResponseAPDU> responses = ResponseAPDU.getResponses(payload, 8);

		assertEquals(3, responses.size());
		assertArrayEquals(payload, join(responses));
	}

	@Test
	public void testStatus() {
		List<ResponseAPDU> responses = ResponseAPDU.getResponses(payload(3), 100, 0x91);

		assertEquals(0x91, responses.get(0).getSW1());
		assertEquals(0x00, responses.get(0).getSW2());
	}

	@Test
	public void testMaxLengthTooShort() {
		// there must be room for some payload (and the header and status bytes)
		for (int maxLength : new int[] { 7, 6, 1, 0, -1, Integer.MIN_VALUE }) {
			assertThrows(IllegalArgumentException.class, () -> ResponseAPDU.getResponses(payload(10), maxLength), "max length " + maxLength);
			assertThrows(IllegalArgumentException.class, () -> ResponseAPDU.getResponses(new byte[0], maxLength), "empty, max length " + maxLength);
		}
	}

}
