package no.entur.abt.bob.mts7.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class Mts7CardEnricherTest {

	@Test
	public void test() {

		Mts7CardEnricher enricher = new Mts7CardEnricher();

		Mts7Card card = new Mts7Card();

		byte[] response = ByteArrayHexStringConverter
				.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");

		enricher.enrichSelectApplicationResponseApdu(card, response);

		assertEquals("0000175F96B61D", ByteArrayHexStringConverter.toHexString(card.getSerial()));
		assertEquals(0x000A, card.getParticipantIdentifier());
		assertEquals(0x1, card.getVersion());

		assertEquals(0x24, card.getSignatureCounter());
		assertEquals(LifecycleStatus.NO_INFORMATION_GIVEN, card.getLifeCycleStatus());

		assertEquals(0x0105, card.getMaximumCommandApduLength());
		assertEquals(0x0102, card.getMaximumResponseApduLength());
	}

	private LifecycleStatus parseLifecycleStatus(String lifecycleStatusByte) {
		Mts7CardEnricher enricher = new Mts7CardEnricher();

		Mts7Card card = new Mts7Card();

		byte[] response = ByteArrayHexStringConverter
				.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01" + lifecycleStatusByte + "7F660802020105020201029000");

		enricher.enrichSelectApplicationResponseApdu(card, response);

		return card.getLifeCycleStatus();
	}

	@Test
	public void testLifecycleStatus() {
		assertEquals(LifecycleStatus.NO_INFORMATION_GIVEN, parseLifecycleStatus("00"));
		assertEquals(LifecycleStatus.INITIALIZATION, parseLifecycleStatus("03"));
		assertEquals(LifecycleStatus.OPERATIONAL, parseLifecycleStatus("05"));
		assertEquals(LifecycleStatus.TERMINATION, parseLifecycleStatus("0C"));
	}

	@Test
	public void testUnknownLifecycleStatus() {
		assertNull(parseLifecycleStatus("FF"));
	}
}
