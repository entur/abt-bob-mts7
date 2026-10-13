package no.entur.abt.mts7.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.utils.ResponseApduStatusCodes;

public class ResponseApduStatusCodesTest {

	private static String code(int sw1, int sw2) {
		return ResponseApduStatusCodes.getResponseCode(new byte[] { (byte) sw1, (byte) sw2 });
	}

	@Test
	public void testResponseApduStatusCodes() {
		String value = ResponseApduStatusCodes.getResponseCode(new byte[] { (byte) 0x90, 0x00 });
		assertEquals("Command correct.", value);
	}

	@Test
	public void testStatusIsTakenFromTheEndOfTheResponse() {
		assertEquals("File or application not found", ResponseApduStatusCodes.getResponseCode(new byte[] { 0x01, 0x02, 0x03, (byte) 0x6A, (byte) 0x82 }));
	}

	@Test
	public void testExactCodes() {
		assertEquals("Wrong length (Lc or Le)", code(0x67, 0x00));
		assertEquals("File or application not found", code(0x6A, 0x82));
		assertEquals("Referenced data not found", code(0x6A, 0x88));
		assertEquals("Incorrect parameters in data field", code(0x6A, 0x80));
		assertEquals("Last command of a chain expected", code(0x68, 0x83));
		assertEquals("Security status not satisfied (Secure Messaging incorrect)", code(0x69, 0x82));
		assertEquals("INS not supported", code(0x6D, 0x00));
		assertEquals("CLA not supported", code(0x6E, 0x00));
	}

	@Test
	public void testSecureMessagingCodes() {
		// as listed in MTS7 table 7
		assertEquals("Secure Messaging DOs incorrect", code(0x62, 0x88));
		assertTrue(code(0x62, 0x87).startsWith("Expected Secure Messaging DOs missing"));
	}

	@Test
	public void testAnySw2() {
		// 61xx: SW2 is the number of bytes still available
		assertEquals("Command correct. SW2 encodes the number of bytes still available in response.", code(0x61, 0x00));
		assertEquals("Command correct. SW2 encodes the number of bytes still available in response.", code(0x61, 0x05));
		assertEquals("Command correct. SW2 encodes the number of bytes still available in response.", code(0x61, 0xFF));
	}

	@Test
	public void testUnknownCodesDoNotMatchSimilarCodes() {
		// 90 AF (additional frame) and 91 00 are not 90 00
		assertNull(code(0x90, 0xAF));
		assertNull(code(0x91, 0x00));
		// 6A 83 is neither 68 83 nor 6A 80 / 6A 82 / 6A 84 / 6A 88
		assertNull(code(0x6A, 0x83));
		assertNull(code(0x6A, 0x99));
		// 6F 00 is not 67 00
		assertNull(code(0x6F, 0x00));
		assertNull(code(0x00, 0x00));
		assertNull(code(0xFF, 0xFF));
	}

	@Test
	public void testResponseTooShort() {
		assertNull(ResponseApduStatusCodes.getResponseCode(new byte[0]));
		assertNull(ResponseApduStatusCodes.getResponseCode(new byte[] { (byte) 0x90 }));
		assertNull(ResponseApduStatusCodes.getResponseCode(null));
	}
}
