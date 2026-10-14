package no.entur.abt.bob.mts7.core.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.test.util.ConcurrentRunner;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * Test that the issuer keys can be shared between threads, as is done when the same {@linkplain ParticipantPublicKeys} is used for all cards.
 */

public class IssuerPublicKeyConcurrencyTest extends AbstractTest {

	private static final CBORMapper CBOR = new CBORMapper();

	private static final long PID = 10;
	private static final String KID = "10:20230213";

	private static final int THREADS = 8;

	// genuine card (without the status words) issued by the above participant and key
	private static final String GET_NEXT_DATA = "A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000";

	private static byte[][] elements;
	private static Map<String, Object> header;

	@SuppressWarnings("unchecked")
	@BeforeAll
	public static void parseCard() throws Exception {
		byte[] response = ByteArrayHexStringConverter.hexStringToByteArray(GET_NEXT_DATA);
		byte[] payload = new byte[response.length - 2];
		System.arraycopy(response, 0, payload, 0, payload.length);

		Map<String, Object> outer = CBOR.readValue(payload, Map.class);

		// the elements which were signed, followed by the signature
		elements = CBOR.readValue((byte[]) outer.get("p"), byte[][].class);

		header = CBOR.readValue(elements[0], Map.class);
	}

	/**
	 * Verify the issuer signature of the card, as the processors do.
	 */

	private void verifyIssuerSignature(IssuerPublicKey issuerPublicKey) throws Exception {
		IccPublicKeyBuilder builder = new IccPublicKeyBuilder(factory);
		for (int i = 0; i < elements.length - 1; i++) {
			builder.withSignedData(elements[i], 0, elements[i].length);
		}

		builder.withSignature(elements[elements.length - 1]).withIssuerPublicKey(issuerPublicKey).withIssuerSignatureProtectedHeader(header);

		assertNotNull(builder.build());
	}

	@Test
	public void testSingleThreadedVerify() throws Exception {
		IssuerPublicKey issuerPublicKey = participantPublicKeys.getIssuerPublicKey(PID, KID);
		assertNotNull(issuerPublicKey);

		verifyIssuerSignature(issuerPublicKey);
	}

	@Test
	public void testSharedIssuerKey() throws Exception {
		IssuerPublicKey issuerPublicKey = participantPublicKeys.getIssuerPublicKey(PID, KID);
		assertNotNull(issuerPublicKey);

		List<Throwable> failures = ConcurrentRunner.run(THREADS, 300, (thread, iteration) -> verifyIssuerSignature(issuerPublicKey));

		assertEquals(0, failures.size(), "Unexpected failures: " + failures);
	}

	@Test
	public void testFirstUseOfLazyKey() throws Exception {
		// the issuer keys are created on first use, so let the threads race for it
		for (int round = 0; round < 30; round++) {
			ParticipantPublicKeys fresh = ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();

			List<Throwable> failures = ConcurrentRunner.run(THREADS, 5, (thread, iteration) -> {
				IssuerPublicKey issuerPublicKey = fresh.getIssuerPublicKey(PID, KID);
				assertNotNull(issuerPublicKey);

				verifyIssuerSignature(issuerPublicKey);
			});

			assertEquals(0, failures.size(), "Unexpected failures in round " + round + ": " + failures);
		}
	}

}
