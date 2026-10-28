package no.entur.abt.bob.mts7.reader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.core.Mts7ApduPayloads;
import no.entur.abt.bob.mts7.core.Mts7ApduPayloadsFactory;
import no.entur.abt.bob.mts7.mtb.IssuerSignatureProtectedHeader;
import no.entur.abt.bob.mts7.mtb.MobileTicketBundle;
import no.entur.abt.bob.mts7.mtb.MobileTicketBundleParser;
import no.entur.abt.bob.mts7.mtb.TokenPublicKey;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchanges;
import no.entur.abt.bob.mts7.simple.reader.Mts7ApduExchangesFactory;
import no.entur.abt.bob.mts7.test.record.CardPlayback;
import no.entur.abt.bob.mts7.test.record.CardRecording;
import no.entur.abt.bob.mts7.test.record.CardRecordingFactory;
import no.entur.abt.bob.mts7.test.record.TransceiveInvocation;
import no.entur.abt.bob.mts7.test.record.bob.Mts7PrettyPrinterCard;
import no.entur.abt.bob.mts7.test.record.bob.Mts7TlvPrettyPrinter;
import no.entur.abt.bob.mts7.test.util.MockRandomFactory;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * Read the Mobile Ticket Bundle from recorded cards (see {@linkplain CardRecordingIntegrationTest}), and check and print the parsed fields.
 */

public class MobileTicketBundleRecordingTest {

	private final MobileTicketBundleParser parser = new MobileTicketBundleParser();

	@Test
	public void testParticipant10Card() throws Exception {
		MobileTicketBundle bundle = readAndParse("/recordings/participant-10-0000175F96B61D.json");

		assertEquals("1", bundle.getMajorVersion());
		assertEquals(2, bundle.getSignedElements().length);
		// empty ticket bundle, definite length
		assertArrayEquals(new byte[] { (byte) 0xA0 }, bundle.getSignedElements()[1]);
		assertEquals(64, bundle.getSignature().length);

		IssuerSignatureProtectedHeader header = bundle.getIssuerSignatureProtectedHeader();
		assertEquals("ES256", header.getAlg());
		assertEquals("10", header.getIid());
		assertEquals("10:20230213", header.getKid());
		assertEquals("6", header.getMiv());
		assertEquals("20230616T110236Z", header.getNbf());
		assertNull(header.getExp());

		assertEcP256TokenPublicKey(header.getTpk(), "gRE1EKw-cG_7AUC0h57-T5WYAnQcDWYru7JwmLGgVfo", "pkQkjVch2T2da_X-KShsQAQZ0jGHZH1ywZGTdVdb6dQ");
	}

	@Test
	public void testParticipant36Card() throws Exception {
		// indefinite length arrays and maps
		MobileTicketBundle bundle = readAndParse("/recordings/participant-36-000114C5C31EBB.json");

		assertEquals("1", bundle.getMajorVersion());
		assertEquals(2, bundle.getSignedElements().length);
		// empty ticket bundle, indefinite length
		assertArrayEquals(new byte[] { (byte) 0xBF, (byte) 0xFF }, bundle.getSignedElements()[1]);
		assertEquals(64, bundle.getSignature().length);

		IssuerSignatureProtectedHeader header = bundle.getIssuerSignatureProtectedHeader();
		assertEquals("ES256", header.getAlg());
		assertEquals("36", header.getIid());
		assertEquals("h2", header.getKid());
		assertEquals("6", header.getMiv());
		assertNull(header.getNbf());
		assertNull(header.getExp());

		assertEcP256TokenPublicKey(header.getTpk(), "FO9oiGZWWKU71dx7XWgCX8LabFTU3R-JR3xVDZv4wbw", "ASYQEMbnkhAz7YuHBjQBbCUa-mN3oB64ast5oAocrII");
	}

	private static void assertEcP256TokenPublicKey(TokenPublicKey tpk, String x, String y) {
		assertNotNull(tpk);
		assertEquals("EC", tpk.getKty());
		assertEquals("P-256", tpk.getCrv());
		assertEquals(x, tpk.getX());
		assertEquals(y, tpk.getY());
		assertNull(tpk.getN());
		assertNull(tpk.getE());
	}

	/**
	 * Replay the recording, checking that the commands are exactly as recorded, and parse the MTB.
	 */

	private MobileTicketBundle readAndParse(String recordingPath) throws Exception {
		CardRecording recording = new CardRecordingFactory().read(recordingPath);

		CardPlayback card = recording.toExactPlayback(true);

		// log each command and response
		Mts7PrettyPrinterCard printerCard = Mts7PrettyPrinterCard.newBuilder().withCard(card).withPrettyPrinter(Mts7TlvPrettyPrinter.getInstance()).build();

		// with the recorded random value, the challenge of internal authenticate is as recorded too
		Mts7ApduExchanges mts7ApduExchanges = new Mts7ApduExchangesFactory(MockRandomFactory.newInstance(recording.getRandomValue()))
				.createCard(new DefaultMts7Card(printerCard), null);
		assertTrue(card.isComplete(), "all the recorded commands were sent");

		Mts7ApduPayloads mts7ApduPayloads = new Mts7ApduPayloadsFactory().createCard(mts7ApduExchanges);

		assertTrue(mts7ApduPayloads.hasGetDataOutput(), "No 'get data' output read from the card");

		byte[] getDataOutput = mts7ApduPayloads.getGetDataOutput();

		// the response to the last get next data, without the status bytes
		List<TransceiveInvocation> invocations = recording.getTransceiveInvocations();
		byte[] getNextDataResponse = invocations.get(invocations.size() - 2).getResponse();
		assertArrayEquals(Arrays.copyOf(getNextDataResponse, getNextDataResponse.length - 2), getDataOutput);

		MobileTicketBundle bundle = parser.parse(getDataOutput);
		assertNotNull(bundle.getIssuerSignatureProtectedHeader(), "No Issuer Signature Protected Header found");

		print(getDataOutput, bundle);

		return bundle;
	}

	private static void print(byte[] getDataOutput, MobileTicketBundle bundle) {
		System.out.println("Raw MTB: " + ByteArrayHexStringConverter.toHexString(getDataOutput));
		System.out.println("Parsed MTB: " + bundle);
	}
}
