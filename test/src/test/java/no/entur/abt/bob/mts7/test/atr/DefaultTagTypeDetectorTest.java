package no.entur.abt.bob.mts7.test.atr;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class DefaultTagTypeDetectorTest {

	private final DefaultTagTypeDetector<Object> detector = new DefaultTagTypeDetector<>();

	private TagType parse(String historicalBytes) {
		return detector.parseHistoricalBytes(null, ByteArrayHexStringConverter.hexStringToByteArray(historicalBytes));
	}

	// historical bytes which are valid, and which gave the same result before the checks of the length were added

	@Test
	public void testKnownTag() {
		// 80 4F 0C A0 00 00 03 06 03 00 03 00 00 00 00
		assertEquals(TagType.MIFARE_ULTRALIGHT, parse("804F0CA0000003060300030000000000"));
	}

	@Test
	public void testNotCompactTlvButUnknownTag() {
		assertEquals(TagType.ISO_DEP, parse("804F0CA000000306030099990000000000"));
	}

	@Test
	public void testAndroidDevice() {
		// first byte of the tag id is 0xFF, but not a known tag
		assertEquals(TagType.ISO_14443_TYPE_A, parse("804F0CA00000030603FF99990000000000"));
	}

	@Test
	public void testOtherCategory() {
		assertEquals(TagType.ISO_DEP, parse("00"));
		assertEquals(TagType.ISO_DEP, parse("10"));
	}

	// historical bytes which are too short, or which are not valid

	@Test
	public void testNoHistoricalBytes() {
		assertEquals(TagType.ISO_DEP, parse(""));
		assertEquals(TagType.ISO_DEP, detector.parseHistoricalBytes(null, null));
	}

	@Test
	public void testOnlyCategory() {
		assertEquals(TagType.ISO_DEP, parse("80"));
	}

	@Test
	public void testInitialAccessDataTooShort() {
		// the tag (4) and length for the initial access data, but nothing, or too little, to read the type of tag from
		assertEquals(TagType.ISO_DEP, parse("8040"));
		assertEquals(TagType.ISO_DEP, parse("8045"));
		assertEquals(TagType.ISO_DEP, parse("804501"));
		assertEquals(TagType.ISO_DEP, parse("8049010203"));
		assertEquals(TagType.ISO_DEP, parse("804F"));
		assertEquals(TagType.ISO_DEP, parse("804F0C"));
		assertEquals(TagType.ISO_DEP, parse("804F0CA00000030603"));
	}

	@Test
	public void testTruncatedAtTheTypeOfTag() {
		// one byte short of the type of the tag
		assertEquals(TagType.ISO_DEP, parse("804F0CA000000306030003000000"));
	}

	@Test
	public void testLengthOfObjectMissing() {
		// the tag of the second object is the last byte
		assertEquals(TagType.ISO_DEP, parse("804F0040"));
		assertEquals(TagType.ISO_DEP, parse("80FF"));
	}

}
