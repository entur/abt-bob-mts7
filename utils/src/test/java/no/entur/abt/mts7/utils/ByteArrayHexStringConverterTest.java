package no.entur.abt.mts7.utils;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class ByteArrayHexStringConverterTest {

	@Test
	public void testHexStringToByteArray() {
		assertArrayEquals(new byte[] { 0x00, (byte) 0xA4, 0x04, 0x00, (byte) 0xFF }, ByteArrayHexStringConverter.hexStringToByteArray("00A40400FF"));
	}

	@Test
	public void testLowerCase() {
		assertArrayEquals(new byte[] { 0x0A, (byte) 0xFF, (byte) 0xBC }, ByteArrayHexStringConverter.hexStringToByteArray("0aFfbC"));
	}

	@Test
	public void testEmpty() {
		assertArrayEquals(new byte[0], ByteArrayHexStringConverter.hexStringToByteArray(""));
	}

	@Test
	public void testRoundtripOfAllBytes() {
		byte[] all = new byte[256];
		for (int i = 0; i < all.length; i++) {
			all[i] = (byte) i;
		}

		String hex = ByteArrayHexStringConverter.toHexString(all);
		assertEquals(512, hex.length());

		assertArrayEquals(all, ByteArrayHexStringConverter.hexStringToByteArray(hex));
		assertArrayEquals(all, ByteArrayHexStringConverter.hexStringToByteArray(hex.toLowerCase()));
	}

	@Test
	public void testOddLength() {
		assertThrows(IllegalArgumentException.class, () -> ByteArrayHexStringConverter.hexStringToByteArray("0"));
		assertThrows(IllegalArgumentException.class, () -> ByteArrayHexStringConverter.hexStringToByteArray("abc"));
		assertThrows(IllegalArgumentException.class, () -> ByteArrayHexStringConverter.hexStringToByteArray("00A40"));
	}

	@Test
	public void testNotHexCharacters() {
		// these used to give bytes (ZZ gave EF, 0x10 gave FF10)
		assertThrows(IllegalArgumentException.class, () -> ByteArrayHexStringConverter.hexStringToByteArray("ZZ"));
		assertThrows(IllegalArgumentException.class, () -> ByteArrayHexStringConverter.hexStringToByteArray("0x10"));
		assertThrows(IllegalArgumentException.class, () -> ByteArrayHexStringConverter.hexStringToByteArray("0g"));
		assertThrows(IllegalArgumentException.class, () -> ByteArrayHexStringConverter.hexStringToByteArray("g0"));
		assertThrows(IllegalArgumentException.class, () -> ByteArrayHexStringConverter.hexStringToByteArray("00 A4"));
		assertThrows(IllegalArgumentException.class, () -> ByteArrayHexStringConverter.hexStringToByteArray(" 0"));
		assertThrows(IllegalArgumentException.class, () -> ByteArrayHexStringConverter.hexStringToByteArray("0\n"));
		assertThrows(IllegalArgumentException.class, () -> ByteArrayHexStringConverter.hexStringToByteArray("-1"));
	}

	@Test
	public void testDigitsWhichAreNotAscii() {
		// Character.digit(..) accepts digits of other scripts
		assertThrows(IllegalArgumentException.class, () -> ByteArrayHexStringConverter.hexStringToByteArray("٣٣"));
		assertThrows(IllegalArgumentException.class, () -> ByteArrayHexStringConverter.hexStringToByteArray("ＡＡ"));
	}

	@Test
	public void testMessageTellsWhichCharacter() {
		IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> ByteArrayHexStringConverter.hexStringToByteArray("00A4Z0"));

		// the position and the character, so that a bad recording can be found
		assertEquals(true, e.getMessage().contains("4"), e.getMessage());
		assertEquals(true, e.getMessage().contains("Z"), e.getMessage());
	}

}
