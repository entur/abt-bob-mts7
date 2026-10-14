package no.entur.abt.bob.mts7.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import no.entur.abt.bob.api.pm.model.ParticipantMetadata;
import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;
import no.entur.abt.bob.mts7.test.util.ConcurrentRunner;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * Test that a single instance of each card factory can be used by several threads at the same time, so that expensive objects can be reused.
 */

public class Mts7CardFactoryConcurrencyTest {

	private static final int THREADS = 8;
	private static final int ITERATIONS = 200;

	private ParticipantPublicKeys participantPublicKeys;
	private Mts7ApduPayloads payloads;

	@BeforeEach
	public void setup() throws Exception {
		InputStream is = getClass().getResourceAsStream("/participantMetadata.json");

		List<ParticipantMetadata> participantMetadata = Arrays.asList(new ObjectMapper().readValue(is, ParticipantMetadata[].class));
		assertFalse(participantMetadata.isEmpty());

		participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();

		byte[] challenge = ByteArrayHexStringConverter.hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000000");
		byte[] selectApplicationResponse = ByteArrayHexStringConverter
				.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");
		byte[] getNextDataResponse = ByteArrayHexStringConverter.hexStringToByteArray(
				"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000");
		byte[] signatureResponse = ByteArrayHexStringConverter.hexStringToByteArray(
				"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");

		payloads = new Mts7ApduPayloads();
		payloads.setSelectApplicationOutput(fromResponseApdu(selectApplicationResponse));
		payloads.setGetDataOutput(fromResponseApdu(getNextDataResponse));
		payloads.setInternalAuthenticateInput(challenge);
		payloads.setInternalAuthenticateOutput(fromResponseApdu(signatureResponse));
	}

	private static byte[] fromResponseApdu(byte[] response) {
		byte[] payload = new byte[response.length - 2];
		System.arraycopy(response, 0, payload, 0, payload.length);
		return payload;
	}

	@FunctionalInterface
	private interface CardFactory {
		Mts7Card create(Mts7ApduPayloads payloads) throws Exception;
	}

	private void assertSharedFactory(CardFactory factory, boolean trustChain) throws Exception {
		// the correct result, from a single thread
		Mts7Card expected = factory.create(payloads);
		assertTrue(expected.isVerifiedPrivateKeyPresent());
		assertEquals(trustChain, expected.isVerifiedTrustChain());
		assertNotNull(expected.getThumbprint());

		List<Throwable> failures = ConcurrentRunner.run(THREADS, ITERATIONS, (thread, iteration) -> {
			Mts7Card card = factory.create(payloads);

			assertTrue(card.isVerifiedPrivateKeyPresent(), "private key");
			assertEquals(trustChain, card.isVerifiedTrustChain(), "trust chain");

			assertArrayEquals(expected.getSerial(), card.getSerial(), "serial");
			assertArrayEquals(expected.getThumbprint(), card.getThumbprint(), "thumbprint");
		});

		assertEquals(0, failures.size(), "Unexpected failures (" + failures.size() + " of " + THREADS * ITERATIONS + "): " + failures);
	}

	@Test
	public void testVerifyMts7CardFactory() throws Exception {
		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(participantPublicKeys);

		assertSharedFactory(factory::create, true);
	}

	@Test
	public void testVerifyKeyPairMts7CardFactory() throws Exception {
		VerifyKeyPairMts7CardFactory factory = new VerifyKeyPairMts7CardFactory();

		assertSharedFactory(factory::create, false);
	}

	@Test
	public void testLenientMts7CardFactory() throws Exception {
		LenientMts7CardFactory factory = new LenientMts7CardFactory();

		assertSharedFactory(factory::create, false);
	}

}
