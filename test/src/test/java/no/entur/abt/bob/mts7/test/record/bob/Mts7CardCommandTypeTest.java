package no.entur.abt.bob.mts7.test.record.bob;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class Mts7CardCommandTypeTest {

	private static Mts7CardCommandType parse(String hex) {
		return Mts7CardCommandType.parseCommandApdu(ByteArrayHexStringConverter.hexStringToByteArray(hex));
	}

	@Test
	public void testExtendedAndShortLength() {
		assertEquals(Mts7CardCommandType.GET_NEXT_DATA_COMMAND, parse("00CC7F21000000"));
		assertEquals(Mts7CardCommandType.GET_NEXT_DATA_COMMAND, parse("00CC7F2100"));

		assertEquals(Mts7CardCommandType.GET_DATA_COMMAND, parse("00CA7F21000000"));
		assertEquals(Mts7CardCommandType.GET_DATA_COMMAND, parse("00CA7F2100"));

		assertEquals(Mts7CardCommandType.GET_RESPONSE, parse("00C0000000000000"));
		assertEquals(Mts7CardCommandType.GET_RESPONSE, parse("00C0000000"));
	}

}
