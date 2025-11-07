package no.entur.abt.bob.mts7.test.atr;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class DefaultTagTypeIdentifierTest {

	private DefaultTagTypeDetector defaultTagTypeIdentifier = new DefaultTagTypeDetector<>();

	@Test
	public void testAtr() {
		TagType result = defaultTagTypeIdentifier.parseAtr(null, ByteArrayHexStringConverter.hexStringToByteArray("3B8F8001804F0CA0000003060300030000000068"));

		assertEquals(TagType.MIFARE_ULTRALIGHT, result);
	}
}
