package no.entur.abt.bob.mts7.reader.processor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Provider;
import java.util.concurrent.ExecutionException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.api.apdu.CommandAPDU;
import no.entur.abt.bob.mts7.core.KeyPairInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.core.Mts7CardEnricher;
import no.entur.abt.bob.mts7.core.NoSuchAlgorithmMts7Exception;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;
import no.entur.abt.bob.mts7.reader.AbstractExecutorTest;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class VerifyKeyPairMts7ProcessorTest extends AbstractExecutorTest {

	// the responses of a genuine card (with status words), the challenge being 32 zero bytes
	private static final String SELECT_APPLICATION_RESPONSE = "64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000";
	private static final String GET_NEXT_DATA_RESPONSE = "A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000";
	private static final String SIGNATURE_RESPONSE = "DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000";

	private VerifyKeyPairMts7ProcessorFactory processorFactory;

	@BeforeEach
	public void setup() throws Exception {
		this.processorFactory = new VerifyKeyPairMts7ProcessorFactory(executor);
	}

	@Test
	public void testSingleProcessorEC() throws Exception {
		Mts7Processor processor = processorFactory.create();

		byte[] selectApplicationResponse = ByteArrayHexStringConverter
				.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");
		processor.onSelectApplication(selectApplicationResponse);

		byte[] getNextDataResponse = ByteArrayHexStringConverter.hexStringToByteArray(
				"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000");
		processor.onGetDataResponseApdu(getNextDataResponse);

		byte[] challenge = ByteArrayHexStringConverter.hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000000");
		assertEquals(challenge.length, 32);
		CommandAPDU command = new CommandAPDU(0, 0, 0, 0, challenge);

		byte[] signatureResponse = ByteArrayHexStringConverter.hexStringToByteArray(
				"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");
		processor.onInternalAuthenticateApdu(command.getBytes(), signatureResponse);

		processor.run();

		Mts7Card card = processor.waitForVerify(0);

		assertTrue(card.isVerifiedPrivateKeyPresent());
		assertFalse(card.isVerifiedTrustChain());

		assertEquals("0000175F96B61D", ByteArrayHexStringConverter.toHexString(card.getSerial()));
	}

	@Test
	public void testCardWithoutPrivateKeyIsRejected() throws Exception {
		// as from a cloned card, which does not have the private key
		assertThrows(KeyPairInvalidCardMts7Exception.class,
				() -> process(processorFactory.create(), SIGNATURE_RESPONSE.replace("DCC5", "DCC6")).waitForVerify(0));
	}

	@Test
	public void testUnavailableSignatureAlgorithmIsNotInvalidCard() throws Exception {
		// a problem with the verifier: the security provider does not have the signature algorithm of the card
		Provider empty = new Provider("Empty", "1.0", "Without algorithms") {
			private static final long serialVersionUID = 1L;
		};
		VerifyKeyPairMts7ProcessorFactory factory = new VerifyKeyPairMts7ProcessorFactory(new IccPublicKeyFactory(empty), new Mts7CardEnricher(),
				new CBORMapper(), new ThumbprintFactory(null), executor);

		ExecutionException e = assertThrows(ExecutionException.class, () -> process(factory.create(), SIGNATURE_RESPONSE).waitForVerify(0));

		assertInstanceOf(NoSuchAlgorithmMts7Exception.class, e.getCause());
	}

	private static Mts7Processor process(Mts7Processor processor, String signatureResponse) {
		processor.onSelectApplicationResponseApdu(ByteArrayHexStringConverter.hexStringToByteArray(SELECT_APPLICATION_RESPONSE));
		processor.onGetDataResponseApdu(ByteArrayHexStringConverter.hexStringToByteArray(GET_NEXT_DATA_RESPONSE));
		processor.onInternalAuthenticateApdu(new CommandAPDU(0, 0, 0, 0, new byte[32]).getBytes(),
				ByteArrayHexStringConverter.hexStringToByteArray(signatureResponse));
		processor.run();
		return processor;
	}

}
