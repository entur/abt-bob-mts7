package no.entur.abt.mts7.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.utils.ResponseApduStatusCodes;

public class ResponseApduStatusCodesTest {

	@Test
	public void testResponseApduStatusCodes() {
		String value = ResponseApduStatusCodes.getResponseCode(new byte[] { (byte) 0x90, 0x00 });
		assertEquals("Command correct.", value);
	}
}
