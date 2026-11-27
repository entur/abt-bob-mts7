package no.entur.abt.bob.mts7.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;
import no.entur.tlv.parser.LenientTlvPullParser;

public class Mts7CardEnricherTest {

	@Test
	public void test() throws Exception {

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

	private LifecycleStatus parseLifecycleStatus(String lifecycleStatusByte) throws Exception {
		Mts7CardEnricher enricher = new Mts7CardEnricher();

		Mts7Card card = new Mts7Card();

		byte[] response = ByteArrayHexStringConverter
				.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01" + lifecycleStatusByte + "7F660802020105020201029000");

		enricher.enrichSelectApplicationResponseApdu(card, response);

		return card.getLifeCycleStatus();
	}

	@Test
	public void testLifecycleStatus() throws Exception {
		assertEquals(LifecycleStatus.NO_INFORMATION_GIVEN, parseLifecycleStatus("00"));
		assertEquals(LifecycleStatus.INITIALIZATION, parseLifecycleStatus("03"));
		assertEquals(LifecycleStatus.OPERATIONAL, parseLifecycleStatus("05"));
		assertEquals(LifecycleStatus.TERMINATION, parseLifecycleStatus("0C"));
	}

	@Test
	public void testUnknownLifecycleStatus() throws Exception {
		assertNull(parseLifecycleStatus("FF"));
	}

	// the card as far as it was enriched, also if the response is rejected
	private Mts7Card enrichPayload(String hex) {
		Mts7Card card = new Mts7Card();

		try {
			new Mts7CardEnricher().enrichSelectApplicationResponsePayload(card, ByteArrayHexStringConverter.hexStringToByteArray(hex));
		} catch (InvalidCardMts7Exception e) {
			// rejected: the card as far as it was enriched
		}

		return card;
	}

	// without a valid application identifier, the response is rejected
	private static void assertRejected(String hex) {
		InvalidCardMts7Exception e = assertThrows(InvalidCardMts7Exception.class,
				() -> new Mts7CardEnricher().enrichSelectApplicationResponsePayload(new Mts7Card(), ByteArrayHexStringConverter.hexStringToByteArray(hex)));

		assertEquals("Missing or malformed application identifier in the select application response", e.getMessage());
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
		assertRejected("64136E114F0F" + APPLICATION_IDENTIFIER.substring(0, 30));

		assertNull(card.getVersion());
		assertNull(card.getParticipantIdentifier());
		assertNull(card.getSerial());
	}

	@Test
	public void testEmptyApplicationIdentifier() {
		Mts7Card card = enrichPayload("64046E024F00");
		assertRejected("64046E024F00");

		assertNull(card.getVersion());
		assertNull(card.getSerial());
	}

	@Test
	public void testApplicationIdentifierTooShortDoesNotHideTheRest() {
		// a too short application identifier, followed by the life-cycle status
		Mts7Card card = enrichPayload("64086E064F01018A0105");
		assertRejected("64086E064F01018A0105");

		assertNull(card.getSerial());
		assertEquals(LifecycleStatus.OPERATIONAL, card.getLifeCycleStatus());
	}

	@Test
	public void testEmptyLifecycleStatus() {
		// no byte for the status, so the byte which follows (05, the next tag, which would be operational) is not the status. There is no application
		// identifier, so the response is rejected, but the card is enriched as far as it goes
		Mts7Card card = enrichPayload("64066E048A000500");
		assertRejected("64066E048A000500");

		assertNull(card.getLifeCycleStatus());
	}

	private static final String AID = "A0000007810101000A0000175F96B61D";

	@Test
	public void testMissingApplicationIdentifierIsInvalidCard() throws Exception {
		// with the status word, as for enrichSelectApplicationResponseApdu
		String[] responses = { "9000", "FFFFFFFFFF9000", "64056E038A01009000", "6E124F10" + AID + "9000", "640B6E094F07A00000078101019000", "6429" + "9000",
				"648480000000" + "6E124F10" + AID + "9000", "64086E064F84800000009000", "90" };

		for (String response : responses) {
			Mts7Card card = new Mts7Card();
			InvalidCardMts7Exception e = assertThrows(InvalidCardMts7Exception.class,
					() -> new Mts7CardEnricher().enrichSelectApplicationResponseApdu(card, ByteArrayHexStringConverter.hexStringToByteArray(response)),
					response);

			assertTrue(e.getMessage().contains("application identifier"), e.getMessage());
			assertNull(card.getSerial());
		}
	}

	@Test
	public void testNullResponseIsInvalidCard() throws Exception {
		InvalidCardMts7Exception e = assertThrows(InvalidCardMts7Exception.class,
				() -> new Mts7CardEnricher().enrichSelectApplicationResponsePayload(new Mts7Card(), null));

		assertInstanceOf(NullPointerException.class, e.getCause());
	}

	@Test
	public void testRuntimeExceptionIsInvalidCard() throws Exception {
		// whatever goes wrong while parsing the response, it is a problem on the card side
		Mts7CardEnricher enricher = new Mts7CardEnricher() {
			@Override
			protected boolean parseApplicationRelatedData(Mts7Card card, LenientTlvPullParser payloadParser) {
				throw new ArrayIndexOutOfBoundsException(-1);
			}
		};

		InvalidCardMts7Exception e = assertThrows(InvalidCardMts7Exception.class,
				() -> enricher.enrichSelectApplicationResponseApdu(new Mts7Card(), ByteArrayHexStringConverter
						.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000")));

		assertEquals("Malformed select application response", e.getMessage());
		assertInstanceOf(ArrayIndexOutOfBoundsException.class, e.getCause());
	}

	@Test
	public void testMalformedDataAfterTheApplicationIdentifierIsIgnored() throws Exception {
		// only the application identifier is required: an overflowing length in the extended length information which follows it is ignored
		Mts7Card card = new Mts7Card();
		new Mts7CardEnricher().enrichSelectApplicationResponseApdu(card,
				ByteArrayHexStringConverter.hexStringToByteArray("641B6E19" + "4F10" + AID + "7F668480000000" + "9000"));

		assertEquals("0000175F96B61D", ByteArrayHexStringConverter.toHexString(card.getSerial()));
		assertEquals(0x000A, card.getParticipantIdentifier());
		assertNull(card.getLifeCycleStatus());
	}

}
