package no.entur.abt.bob.mts7.reader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.reader.processor.Mts7ProcessorFactory;
import no.entur.abt.bob.mts7.reader.processor.VerifyKeyPairMts7ProcessorFactory;
import no.entur.abt.bob.mts7.reader.processor.VerifyTrustChainMts7ProcessorFactory;
import no.entur.abt.bob.mts7.test.ListResponseCard;
import no.entur.abt.bob.mts7.test.util.ConcurrentRunner;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * Test that a single factory (and so the helpers it shares between the processors it creates) can be used by several card readers at the same time, which is
 * how the factories are meant to be used.
 */

public class ParallelReadsTest extends AbstractTest {

	private static final byte[] SELECT_APPLICATION_RESPONSE = ByteArrayHexStringConverter
			.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");
	private static final byte[] GET_NEXT_DATA_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000");
	private static final byte[] SIGNATURE_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");

	// the signature response is for a challenge of all zeroes, and a thread safe source of that
	private static final Random ZERO_RANDOM = new Random() {

		private static final long serialVersionUID = 1L;

		@Override
		public void nextBytes(byte[] bytes) {
			java.util.Arrays.fill(bytes, (byte) 0);
		}
	};

	private static ListResponseCard newCard() {
		ListResponseCard card = new ListResponseCard();
		card.add(SELECT_APPLICATION_RESPONSE);
		card.add(GET_NEXT_DATA_RESPONSE);
		card.add(SIGNATURE_RESPONSE);
		return card;
	}

	private void assertParallelReads(Mts7ProcessorFactory processorFactory, boolean trustChain, int readers, int readsPerReader) throws Exception {
		InFlightMts7CardFactory factory = new InFlightMts7CardFactory(processorFactory, ZERO_RANDOM);

		List<Throwable> failures = ConcurrentRunner.run(readers, readsPerReader, (thread, iteration) -> {
			try (InFlightMts7Card inFlightCard = factory.create(new DefaultMts7Card(newCard()), null)) {
				Mts7Card card = inFlightCard.getMts7Card(0);

				assertTrue(card.isVerifiedPrivateKeyPresent(), "private key");
				assertEquals(trustChain, card.isVerifiedTrustChain(), "trust chain");

				assertEquals("0000175F96B61D", ByteArrayHexStringConverter.toHexString(card.getSerial()));
				assertTrue(card.hasThumprint(), "thumbprint");
			}
		});

		assertEquals(0, failures.size(), "Unexpected failures (" + failures.size() + " of " + readers * readsPerReader + "): " + failures);
	}

	@Test
	public void testThreeReadersVerifyKeyPair() throws Exception {
		assertParallelReads(new VerifyKeyPairMts7ProcessorFactory(), false, 3, 30);
	}

	@Test
	public void testThreeReadersVerifyTrustChain() throws Exception {
		assertParallelReads(new VerifyTrustChainMts7ProcessorFactory(participantPublicKeys), true, 3, 30);
	}

	@Test
	public void testManyReadersVerifyTrustChain() throws Exception {
		assertParallelReads(new VerifyTrustChainMts7ProcessorFactory(participantPublicKeys), true, 16, 10);
	}

	@Test
	public void testWarmedUpFactoryIsStillCorrect() throws Exception {
		VerifyTrustChainMts7ProcessorFactory processorFactory = new VerifyTrustChainMts7ProcessorFactory(participantPublicKeys);

		assertTrue(participantPublicKeys.warmUp().isEmpty());
		processorFactory.warmUp();

		assertParallelReads(processorFactory, true, 3, 10);
	}

}
