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

	private Mts7Card enrichPayload(String hex) {
		Mts7Card card = new Mts7Card();

		new Mts7CardEnricher().enrichSelectApplicationResponsePayload(card, ByteArrayHexStringConverter.hexStringToByteArray(hex));

		return card;
	}

	// the 16 bytes of the application identifier: A0000007810101 + version, pid and serial
	private static final String APPLICATION_IDENTIFIER = "A0000007810101000A0000175F96B61D";

	@Test
	public void testCompleteApplicationIdentifier() {
		// guard for the tests below: 64 <len> 6E <len> 4F 10 <16 bytes>
		Mts7Card card = enrichPayload("64146E124F10" + APPLICATION_IDENTIFIER);

		assertEquals(0x1, card.getVersion());
		assertEquals(0x000A, card.getParticipantIdentifier());
		assertEquals("0000175F96B61D", ByteArrayHexStringConverter.toHexString(card.getSerial()));
	}

	@Test
	public void testApplicationIdentifierTooShort() {
		// 15 of the 16 bytes
		Mts7Card card = enrichPayload("64136E114F0F" + APPLICATION_IDENTIFIER.substring(0, 30));

		assertNull(card.getVersion());
		assertNull(card.getParticipantIdentifier());
		assertNull(card.getSerial());
	}

	@Test
	public void testEmptyApplicationIdentifier() {
		Mts7Card card = enrichPayload("64046E024F00");

		assertNull(card.getVersion());
		assertNull(card.getSerial());
	}

	@Test
	public void testApplicationIdentifierTooShortDoesNotHideTheRest() {
		// a too short application identifier, followed by the life-cycle status
		Mts7Card card = enrichPayload("64086E064F01018A0105");

		assertNull(card.getSerial());
		assertEquals(LifecycleStatus.OPERATIONAL, card.getLifeCycleStatus());
	}

	@Test
	public void testEmptyLifecycleStatus() {
		// no byte for the status, so the byte which follows (05, the next tag, which would be operational) is not the status
		Mts7Card card = enrichPayload("64066E048A000500");

		assertNull(card.getLifeCycleStatus());
	}
}
