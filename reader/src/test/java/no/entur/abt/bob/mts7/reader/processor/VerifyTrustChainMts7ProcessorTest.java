package no.entur.abt.bob.mts7.reader.processor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import no.entur.abt.bob.api.pm.model.MtbJwkPublic;
import no.entur.abt.bob.mts7.api.apdu.CommandAPDU;
import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.core.UnableToVerifyKeyPairException;
import no.entur.abt.bob.mts7.core.UnableToVerifyTrustChainException;
import no.entur.abt.bob.mts7.core.pki.IssuerPublicKey;
import no.entur.abt.bob.mts7.core.pki.IssuerSignatureFactory;
import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;
import no.entur.abt.bob.mts7.reader.AbstractTest;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class VerifyTrustChainMts7ProcessorTest extends AbstractTest {

	// the responses of a genuine card (with status words), the challenge being 32 zero bytes; its issuer is participant 10, key 10:20230213
	private static final String SELECT_APPLICATION_RESPONSE = "64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000";
	private static final String GET_NEXT_DATA_RESPONSE = "A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000";
	private static final String SIGNATURE_RESPONSE = "DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000";
	// as from a cloned card, which does not have the private key
	private static final String OTHER_SIGNATURE_RESPONSE = SIGNATURE_RESPONSE.replace("DCC5", "DCC6");

	private VerifyTrustChainMts7ProcessorFactory processorFactory;

	@BeforeEach
	public void setup() throws Exception {
		super.setup();
		this.processorFactory = new VerifyTrustChainMts7ProcessorFactory(participantPublicKeys, executor);
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
		assertTrue(card.isVerifiedTrustChain());

		assertEquals("0000175F96B61D", ByteArrayHexStringConverter.toHexString(card.getSerial()));
	}

	@Test
	public void testInvalidIssuerSignatureEC() throws Exception {
		Mts7Processor processor = processorFactory.create();

		byte[] selectApplicationResponse = ByteArrayHexStringConverter
				.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");
		processor.onSelectApplication(selectApplicationResponse);

		byte[] getNextDataResponse = ByteArrayHexStringConverter.hexStringToByteArray(
				"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000");

		// the issuer signature is the last 64 bytes before the status bytes
		for (int i = getNextDataResponse.length - 2 - 64; i < getNextDataResponse.length - 2; i++) {
			getNextDataResponse[i] = 0x42;
		}
		processor.onGetDataResponseApdu(getNextDataResponse);

		byte[] challenge = ByteArrayHexStringConverter.hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000000");
		CommandAPDU command = new CommandAPDU(0, 0, 0, 0, challenge);

		byte[] signatureResponse = ByteArrayHexStringConverter.hexStringToByteArray(
				"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");
		processor.onInternalAuthenticateApdu(command.getBytes(), signatureResponse);

		processor.run();

		Mts7Card card;
		try {
			card = processor.waitForVerify(0);
			fail("Expected card not to be trusted");
		} catch (UnableToVerifyKeyPairException e) {
			card = e.getResult();
		} catch (UnableToVerifyTrustChainException e) {
			card = e.getResult();
		}
		assertFalse(card.isVerifiedTrustChain());
	}

	@Test
	public void testUnknownRootKeyIsRejectedByDefault() throws Exception {
		VerifyTrustChainMts7ProcessorFactory factory = new VerifyTrustChainMts7ProcessorFactory(ParticipantPublicKeys.newBuilder().build(), executor);

		assertFalse(factory.isTrustUnknownRootKeys());
		UnableToVerifyKeyPairException e = assertThrows(UnableToVerifyKeyPairException.class,
				() -> process(factory.create(), GET_NEXT_DATA_RESPONSE, SIGNATURE_RESPONSE).waitForVerify(0));
		assertFalse(e.getResult().isVerifiedTrustChain());
	}

	@Test
	public void testUnknownRootKeyIsTrustedWithOption() throws Exception {
		VerifyTrustChainMts7ProcessorFactory factory = new VerifyTrustChainMts7ProcessorFactory(ParticipantPublicKeys.newBuilder().build(), null, true,
				executor);

		Mts7Card card = process(factory.create(), GET_NEXT_DATA_RESPONSE, SIGNATURE_RESPONSE).waitForVerify(0);

		assertTrue(factory.isTrustUnknownRootKeys());
		assertTrue(card.isVerifiedPrivateKeyPresent());
		assertFalse(card.isVerifiedTrustChain());
		assertEquals("0000175F96B61D", ByteArrayHexStringConverter.toHexString(card.getSerial()));
	}

	@Test
	public void testUnknownRootKeyWithoutPrivateKeyIsRejectedWithOption() throws Exception {
		VerifyTrustChainMts7ProcessorFactory factory = new VerifyTrustChainMts7ProcessorFactory(ParticipantPublicKeys.newBuilder().build(), null, true,
				executor);

		assertThrows(UnableToVerifyKeyPairException.class, () -> process(factory.create(), GET_NEXT_DATA_RESPONSE, OTHER_SIGNATURE_RESPONSE).waitForVerify(0));
	}

	@Test
	public void testKnownRootKeyIsVerifiedWithOption() throws Exception {
		VerifyTrustChainMts7ProcessorFactory factory = new VerifyTrustChainMts7ProcessorFactory(participantPublicKeys, null, true, executor);

		Mts7Card card = process(factory.create(), GET_NEXT_DATA_RESPONSE, SIGNATURE_RESPONSE).waitForVerify(0);

		assertTrue(card.isVerifiedPrivateKeyPresent());
		assertTrue(card.isVerifiedTrustChain());
	}

	@Test
	public void testInvalidIssuerSignatureIsRejectedWithOption() throws Exception {
		VerifyTrustChainMts7ProcessorFactory factory = new VerifyTrustChainMts7ProcessorFactory(participantPublicKeys, null, true, executor);
		byte[] getNextDataResponse = ByteArrayHexStringConverter.hexStringToByteArray(GET_NEXT_DATA_RESPONSE);
		// the issuer signature is the last 64 bytes before the status bytes
		for (int i = getNextDataResponse.length - 2 - 64; i < getNextDataResponse.length - 2; i++) {
			getNextDataResponse[i] = 0x42;
		}

		UnableToVerifyKeyPairException e = assertThrows(UnableToVerifyKeyPairException.class,
				() -> process(factory.create(), ByteArrayHexStringConverter.toHexString(getNextDataResponse), SIGNATURE_RESPONSE).waitForVerify(0));

		assertFalse(e.getResult().isVerifiedTrustChain());
	}

	@Test
	public void testKnownUnsupportedRootKeyIsRejectedWithOption() throws Exception {
		VerifyTrustChainMts7ProcessorFactory factory = new VerifyTrustChainMts7ProcessorFactory(unsupportedRootKey(), null, true, executor);

		UnableToVerifyKeyPairException e = assertThrows(UnableToVerifyKeyPairException.class,
				() -> process(factory.create(), GET_NEXT_DATA_RESPONSE, SIGNATURE_RESPONSE).waitForVerify(0));

		assertFalse(e.getResult().isVerifiedTrustChain());
	}

	// the root key of the card is among the issuer keys, but its type is not supported
	private static ParticipantPublicKeys unsupportedRootKey() throws Exception {
		IssuerSignatureFactory unsupported = new IssuerSignatureFactory() {
			@Override
			public IssuerPublicKey createIssuerPublicKey(long pid, MtbJwkPublic jwkPublic) {
				return null;
			}
		};

		Map<String, ParticipantPublicKeys.IssuerKey> keys = new HashMap<>();
		keys.put("10:20230213", new ParticipantPublicKeys.IssuerKey(new MtbJwkPublic().kty("EC").kid("10:20230213")));

		Map<Long, ParticipantPublicKeys.Issuer> issuers = new HashMap<>();
		issuers.put(10L, new ParticipantPublicKeys.Issuer("Ten", 10L, keys, unsupported));

		return new ParticipantPublicKeys(issuers);
	}

	private static Mts7Processor process(Mts7Processor processor, String getNextDataResponse, String signatureResponse) {
		processor.onSelectApplication(ByteArrayHexStringConverter.hexStringToByteArray(SELECT_APPLICATION_RESPONSE));
		processor.onGetDataResponseApdu(ByteArrayHexStringConverter.hexStringToByteArray(getNextDataResponse));
		CommandAPDU command = new CommandAPDU(0, 0, 0, 0, new byte[32]);
		processor.onInternalAuthenticateApdu(command.getBytes(), ByteArrayHexStringConverter.hexStringToByteArray(signatureResponse));
		processor.run();
		return processor;
	}

}
