package no.entur.abt.bob.mts7.test.record;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

public class AbstractCardRecordingAnalyzerTest {

	private static class Analyzer extends AbstractCardRecordingAnalyzer {

		public String name(byte[] command) {
			return getCommandName(command);
		}
	}

	private static byte[] apdu(int... bytes) {
		byte[] result = new byte[bytes.length];
		for (int i = 0; i < bytes.length; i++) {
			result[i] = (byte) bytes[i];
		}
		return result;
	}

	@Test
	public void testClassAndInstruction() {
		Analyzer analyzer = new Analyzer();
		analyzer.addCommandIdentifier(0x00, 0xA4, "Select");

		assertEquals("Select", analyzer.name(apdu(0x00, 0xA4, 0x04, 0x00, 0x06)));
		assertNull(analyzer.name(apdu(0x00, 0xCA, 0x04, 0x00, 0x06)));
	}

	@Test
	public void testHeader() {
		Analyzer analyzer = new Analyzer();
		analyzer.addCommandIdentifier(0x00, 0xCA, 0x7F, 0x21, "Get data");

		assertEquals("Get data", analyzer.name(apdu(0x00, 0xCA, 0x7F, 0x21, 0x00, 0x00, 0x00)));
		assertNull(analyzer.name(apdu(0x00, 0xCA, 0x7F, 0x22, 0x00, 0x00, 0x00)));
	}

	@Test
	public void testBytesAbove0x7f() {
		// the bytes of the command are signed, the identifier is not
		Analyzer analyzer = new Analyzer();
		analyzer.addCommandIdentifier(new int[] { 0x90, 0xAF, 0xFF }, "High");

		assertEquals("High", analyzer.name(apdu(0x90, 0xAF, 0xFF, 0x00)));
	}

	@Test
	public void testWildcard() {
		Analyzer analyzer = new Analyzer();
		analyzer.addCommandIdentifier(new int[] { 0x00, 0xA4, -1, 0x00 }, "Select with any P1");

		assertEquals("Select with any P1", analyzer.name(apdu(0x00, 0xA4, 0x04, 0x00)));
		assertEquals("Select with any P1", analyzer.name(apdu(0x00, 0xA4, 0x00, 0x00)));
		assertNull(analyzer.name(apdu(0x00, 0xA4, 0x04, 0x01)));
	}

	@Test
	public void testCommandShorterThanIdentifier() {
		Analyzer analyzer = new Analyzer();
		analyzer.addCommandIdentifier(0x00, 0xCA, 0x7F, 0x21, "Get data");

		assertNull(analyzer.name(apdu(0x00, 0xCA)));
		assertNull(analyzer.name(new byte[0]));
	}

}
