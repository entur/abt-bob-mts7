package no.entur.abt.bob.mts7.reader;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.core.Mts7ApduPayloads;
import no.entur.abt.bob.mts7.core.Mts7ApduPayloadsFactory;
import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.core.VerifyKeyPairMts7CardFactory;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchanges;
import no.entur.abt.bob.mts7.simple.reader.Mts7ApduExchangesFactory;
import no.entur.abt.bob.mts7.simple.reader.Mts7Exchange;
import no.entur.abt.bob.mts7.test.ExternalReaderCard;
import no.entur.abt.bob.mts7.test.ExternalReaderCardFactory;
import no.entur.abt.bob.mts7.test.record.CardInvocationRecorderCard;
import no.entur.abt.bob.mts7.test.record.CardRecordingFactory;
import no.entur.abt.bob.mts7.test.util.MockRandomFactory;

/**
 * Record a card using a connected card reader, for playback in the tests. The name of the recording is given by the system property <code>recording</code>, for
 * example:
 *
 * <pre>
 * mvn test -pl reader -Dtest=CardRecordingIntegrationTest -Drecording=participant-10
 * </pre>
 *
 * The recording is written to <code>src/test/resources/recordings/[name].json</code>.
 */

public class CardRecordingIntegrationTest {

	private static final File RECORDINGS = new File("src/test/resources/recordings");

	@Test
	public void testRecordCard() throws Exception {
		String name = System.getProperty("recording");
		assertNotNull(name, "Name of the recording (system property 'recording') is missing");

		// the challenge of internal authenticate, saved with the recording so that the playback sends the same commands
		byte[] randomValue = new byte[32];
		new SecureRandom().nextBytes(randomValue);

		try (ExternalReaderCard externalReaderCard = new ExternalReaderCardFactory().createCard(60000)) {
			CardInvocationRecorderCard card = new CardInvocationRecorderCard(externalReaderCard);

			Mts7Exchange exchange = new Mts7Exchange() {
				@Override
				public byte[] getTagId() {
					return null;
				}

				@Override
				public byte[] transceive(byte[] command) throws IOException {
					return card.transceive(command);
				}
			};

			Mts7ApduExchanges exchanges = new Mts7ApduExchangesFactory(MockRandomFactory.newInstance(randomValue)).createCard(exchange, null);

			// only save a complete and valid read
			Mts7ApduPayloads payloads = new Mts7ApduPayloadsFactory().createCard(exchanges);
			Mts7Card mts7Card = new VerifyKeyPairMts7CardFactory().create(payloads);
			assertTrue(mts7Card.isVerifiedPrivateKeyPresent());

			RECORDINGS.mkdirs();
			File file = new File(RECORDINGS, name + ".json");
			new CardRecordingFactory().write(randomValue, LocalDateTime.now(), card, file);

			System.out
					.println("Recorded participant " + mts7Card.getParticipantIdentifier() + " with " + card.getInvocations().size() + " commands to " + file);
		}
	}

}
