package no.entur.abt.bob.mts7.reader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Random;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.reader.processor.VerifyKeyPairMts7ProcessorFactory;
import no.entur.abt.bob.mts7.test.SlowListResponseCard;
import no.entur.abt.bob.mts7.test.util.MockRandomFactory;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;
import no.entur.abt.bob.mts7.utils.nfc.Card;

public class InFlightMts7CardFactoryTest {

	private VerifyKeyPairMts7ProcessorFactory processorFactory;
	private InFlightMts7CardFactory factory;

	@BeforeEach
	public void setup() throws Exception {
		byte[] challenge = ByteArrayHexStringConverter.hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000000");

		Random random = MockRandomFactory.newInstance(challenge);
		this.processorFactory = new VerifyKeyPairMts7ProcessorFactory();
		this.factory = new InFlightMts7CardFactory(processorFactory, random);
	}

	@Test
	public void testMultithreadedEC() throws Exception {
		byte[] selectApplicationResponse = ByteArrayHexStringConverter
				.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");
		byte[] getNextDataResponse = ByteArrayHexStringConverter.hexStringToByteArray(
				"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000");
		byte[] signatureResponse = ByteArrayHexStringConverter.hexStringToByteArray(
				"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");

		Card card = mock(Card.class);
		when(card.transceive(any(byte[].class))).thenReturn(selectApplicationResponse).thenReturn(getNextDataResponse).thenReturn(signatureResponse);

		InFlightMts7Card inflightCard = factory.create(new DefaultMts7Card(card), null);

		Mts7Card parsed = inflightCard.getMts7Card(0);

		assertTrue(parsed.isVerifiedPrivateKeyPresent());
		assertFalse(parsed.isVerifiedTrustChain());

		assertEquals("0000175F96B61D", ByteArrayHexStringConverter.toHexString(parsed.getSerial()));
	}

	@Test
	public void testMultithreadedWithDelayEC() throws Exception {
		byte[] selectApplicationResponse = ByteArrayHexStringConverter
				.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");
		byte[] getNextDataResponse = ByteArrayHexStringConverter.hexStringToByteArray(
				"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000");
		byte[] signatureResponse = ByteArrayHexStringConverter.hexStringToByteArray(
				"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");

		SlowListResponseCard card = new SlowListResponseCard();

		card.add(selectApplicationResponse, 50);
		card.add(getNextDataResponse, 50);
		card.add(signatureResponse, 50);

		long timestamp = System.currentTimeMillis();

		InFlightMts7Card inflightCard = factory.create(new DefaultMts7Card(card), null);

		System.out.println("Begin request after " + (System.currentTimeMillis() - timestamp) + "ms (minimum was " + card.getTotalDelay() + ")");

		Mts7Card parsed = inflightCard.getMts7Card(0);

		System.out.println("Ready for offline fallback in " + (System.currentTimeMillis() - timestamp) + "ms (minimum was " + card.getTotalDelay() + ")");

		assertTrue(parsed.isVerifiedPrivateKeyPresent());
		assertFalse(parsed.isVerifiedTrustChain());

		assertEquals("0000175F96B61D", ByteArrayHexStringConverter.toHexString(parsed.getSerial()));
	}

}
