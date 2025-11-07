package no.entur.abt.bob.mts7.example;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import no.entur.abt.bob.api.pm.model.ParticipantMetadata;
import no.entur.abt.bob.mts7.core.Mts7ApduPayloads;
import no.entur.abt.bob.mts7.core.Mts7ApduPayloadsFactory;
import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.core.VerifyMts7CardFactory;
import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchanges;
import no.entur.abt.bob.mts7.simple.reader.Mts7ApduExchangesFactory;
import no.entur.abt.bob.mts7.simple.reader.Mts7Exchange;
import no.entur.abt.bob.mts7.test.ExternalReaderCard;
import no.entur.abt.bob.mts7.test.ExternalReaderCardFactory;
import no.entur.abt.bob.mts7.test.record.bob.Mts7PrettyPrinterCard;
import no.entur.abt.bob.mts7.test.record.bob.Mts7TlvPrettyPrinter;
import no.entur.abt.bob.mts7.utils.nfc.Card;

public class ExternalReaderCardFactoryIntegrationTest {

	protected static final ObjectMapper mapper = new ObjectMapper();

	protected static ParticipantPublicKeys participantPublicKeys;

	@BeforeAll
	public static void setup() throws Exception {
		InputStream is = ExternalReaderCardFactoryIntegrationTest.class.getResourceAsStream("/participantMetadata.json");

		List<ParticipantMetadata> participantMetadata = Arrays.asList(mapper.readValue(is, ParticipantMetadata[].class));
		assertFalse(participantMetadata.isEmpty());

		participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();
	}

	public static class DefaultMts7Card implements Mts7Exchange {

		private final Card card;

		public DefaultMts7Card(Card card) {
			this.card = card;
		}

		@Override
		public byte[] getTagId() {
			return null;
		}

		@Override
		public byte[] transceive(byte[] data) throws IOException {
			return card.transceive(data);
		}

	}

	@Test
	public void testConnect() throws Exception {
		ExternalReaderCardFactory factory = new ExternalReaderCardFactory();

		Mts7ApduExchangesFactory mts7ApduExchangesFactory = new Mts7ApduExchangesFactory();
		Mts7ApduPayloadsFactory mts7ApduPayloadsFactory = new Mts7ApduPayloadsFactory();

		VerifyMts7CardFactory mts7CardFactory = new VerifyMts7CardFactory(participantPublicKeys);

		try (ExternalReaderCard card = factory.createCard(10000)) {
			long timestamp = System.currentTimeMillis();
			System.out.println("Got card " + card);

			Mts7PrettyPrinterCard tlvPrinterCard = Mts7PrettyPrinterCard.newBuilder()
					.withCard(card)
					.withPrettyPrinter(Mts7TlvPrettyPrinter.getInstance())
					.build();

			Mts7ApduExchanges mts7ApduExchanges = mts7ApduExchangesFactory.createCard(new DefaultMts7Card(tlvPrinterCard), null);
			Mts7ApduPayloads mts7ApduPayloads = mts7ApduPayloadsFactory.createCard(mts7ApduExchanges);

			Mts7Card mts7Card = mts7CardFactory.create(mts7ApduPayloads);

			System.out.println("MTS7 processed in " + (System.currentTimeMillis() - timestamp) + "ms");

			if (mts7Card.isVerifiedPrivateKeyPresent()) {
				System.out.println("Verified private key is present");
			} else {
				System.out.println("NOT Verified private key is present");
			}

			if (mts7Card.isVerifiedTrustChain()) {
				System.out.println("Verified trust chain");
			} else {
				System.out.println("NOT verified trust chain");
			}

		}
	}
}
