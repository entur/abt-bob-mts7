package no.entur.abt.bob.mts7.example;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.api.UnexpectedCardResponseException;
import no.entur.abt.bob.mts7.core.Mts7ApduPayloads;
import no.entur.abt.bob.mts7.core.Mts7ApduPayloadsFactory;
import no.entur.abt.bob.mts7.core.mtb.IssuerSignatureProtectedHeader;
import no.entur.abt.bob.mts7.core.mtb.MobileTicketBundle;
import no.entur.abt.bob.mts7.core.mtb.MobileTicketBundleParser;
import no.entur.abt.bob.mts7.core.mtb.TokenPublicKey;
import no.entur.abt.bob.mts7.example.ExternalReaderCardFactoryIntegrationTest.DefaultMts7Card;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchanges;
import no.entur.abt.bob.mts7.simple.reader.Mts7ApduExchangesFactory;
import no.entur.abt.bob.mts7.test.ExternalReaderCard;
import no.entur.abt.bob.mts7.test.ExternalReaderCardFactory;
import no.entur.abt.bob.mts7.test.record.bob.Mts7PrettyPrinterCard;
import no.entur.abt.bob.mts7.test.record.bob.Mts7TlvPrettyPrinter;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * Read the Mobile Ticket Bundle from a physical card using a connected card reader, and print the parsed fields.
 */

public class MobileTicketBundleIntegrationTest {

	@Test
	public void testReadAndParseMobileTicketBundle() throws Exception {
		ExternalReaderCardFactory factory = new ExternalReaderCardFactory();

		Mts7ApduExchangesFactory mts7ApduExchangesFactory = new Mts7ApduExchangesFactory();
		Mts7ApduPayloadsFactory mts7ApduPayloadsFactory = new Mts7ApduPayloadsFactory();

		MobileTicketBundleParser parser = new MobileTicketBundleParser();

		// generous timeout, so that there is time to place the card on the reader
		try (ExternalReaderCard card = factory.createCard(60000)) {
			System.out.println("Got card " + card);

			// log each command and response
			Mts7PrettyPrinterCard printerCard = Mts7PrettyPrinterCard.newBuilder().withCard(card).withPrettyPrinter(Mts7TlvPrettyPrinter.getInstance()).build();

			Mts7ApduExchanges mts7ApduExchanges;
			try {
				mts7ApduExchanges = mts7ApduExchangesFactory.createCard(new DefaultMts7Card(printerCard), null);
			} catch (UnexpectedCardResponseException e) {
				System.out.println("Unexpected card response");
				System.out.println("  command:  " + ByteArrayHexStringConverter.toHexString(e.getCommand()));
				System.out.println("  response: " + ByteArrayHexStringConverter.toHexString(e.getResponse()));
				throw e;
			}
			Mts7ApduPayloads mts7ApduPayloads = mts7ApduPayloadsFactory.createCard(mts7ApduExchanges);

			assertTrue(mts7ApduPayloads.hasGetDataOutput(), "No 'get data' output read from the card");

			byte[] getDataOutput = mts7ApduPayloads.getGetDataOutput();
			System.out.println("Raw MTB: " + ByteArrayHexStringConverter.toHexString(getDataOutput));

			MobileTicketBundle bundle = parser.parse(getDataOutput);

			System.out.println("Major version (v): " + bundle.getMajorVersion());
			System.out.println("Signed elements: " + bundle.getSignedElements().length);
			for (int i = 0; i < bundle.getSignedElements().length; i++) {
				System.out.println("  [" + i + "]: " + ByteArrayHexStringConverter.toHexString(bundle.getSignedElements()[i]));
			}
			System.out.println("Signature: " + ByteArrayHexStringConverter.toHexString(bundle.getSignature()));

			IssuerSignatureProtectedHeader header = bundle.getIssuerSignatureProtectedHeader();
			assertNotNull(header, "No Issuer Signature Protected Header found");

			System.out.println("Issuer Signature Protected Header:");
			System.out.println("  alg: " + header.getAlg());
			System.out.println("  iid: " + header.getIid());
			System.out.println("  kid: " + header.getKid());
			System.out.println("  miv: " + header.getMiv());
			System.out.println("  exp: " + header.getExp());
			System.out.println("  nbf: " + header.getNbf());
			System.out.println("  dsp: " + header.getDsp());
			System.out.println("  dsi: " + header.getDsi());

			TokenPublicKey tpk = header.getTpk();
			if (tpk != null) {
				System.out.println("  tpk:");
				System.out.println("    kty: " + tpk.getKty());
				System.out.println("    crv: " + tpk.getCrv());
				System.out.println("    x: " + tpk.getX());
				System.out.println("    y: " + tpk.getY());
				System.out.println("    n: " + tpk.getN());
				System.out.println("    e: " + tpk.getE());
			} else {
				System.out.println("  tpk: null");
			}
		}
	}
}
