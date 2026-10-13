package no.entur.abt.bob.mts7.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

public class LifecycleStatusTest {

	@Test
	public void testCodes() {
		assertEquals(0x00, LifecycleStatus.NO_INFORMATION_GIVEN.getCode());
		assertEquals(0x03, LifecycleStatus.INITIALIZATION.getCode());
		assertEquals(0x05, LifecycleStatus.OPERATIONAL.getCode());
		assertEquals(0x0C, LifecycleStatus.TERMINATION.getCode());
	}

	@Test
	public void testParseEveryStatusFromItsCode() {
		for (LifecycleStatus status : LifecycleStatus.values()) {
			assertEquals(status, LifecycleStatus.parse(status.getCode()), status.name());
		}
	}

	@Test
	public void testParseSpecificCodes() {
		assertEquals(LifecycleStatus.NO_INFORMATION_GIVEN, LifecycleStatus.parse(0x00));
		assertEquals(LifecycleStatus.INITIALIZATION, LifecycleStatus.parse(0x03));
		assertEquals(LifecycleStatus.OPERATIONAL, LifecycleStatus.parse(0x05));
		assertEquals(LifecycleStatus.TERMINATION, LifecycleStatus.parse(0x0C));
	}

	@Test
	public void testParseUnknownCode() {
		assertNull(LifecycleStatus.parse(0x01));
		assertNull(LifecycleStatus.parse(0x04));
		// not the termination code
		assertNull(LifecycleStatus.parse(0x12));
		assertNull(LifecycleStatus.parse(0xFF));
		assertNull(LifecycleStatus.parse(-1));
	}

}
