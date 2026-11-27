package no.entur.abt.bob.mts7.reader.processor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.api.pm.model.MtbJwkPublic;
import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.api.apdu.CommandAPDU;
import no.entur.abt.bob.mts7.core.KeyPairInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.core.Mts7CardEnricher;
import no.entur.abt.bob.mts7.core.NoSuchAlgorithmMts7Exception;
import no.entur.abt.bob.mts7.core.OutdatedIssuerKeysException;
import no.entur.abt.bob.mts7.core.TrustChainInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.UnableToConstructIssuerKeyException;
import no.entur.abt.bob.mts7.core.UnknownIssuerKeyInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.UnknownIssuerKeyPolicy;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.IssuerPublicKey;
import no.entur.abt.bob.mts7.core.pki.IssuerSignatureFactory;
import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;
import no.entur.abt.bob.mts7.reader.AbstractTest;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class VerifyTrustChainMts7ProcessorTest extends AbstractTest {

	// the responses of a genuine card (with status words), the challenge being 32 zero bytes; its issuer is participant 10, key 10:20230213
	private static final String SELECT_APPLICATION_RESPONSE = "64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000";
	private static final String GET_NEXT_DATA_RESPONSE = "A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000";
	private static final String SIGNATURE_RESPONSE = "DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000";
	// as from a cloned card, which does not have the private key
	private static final String OTHER_SIGNATURE_RESPONSE = SIGNATURE_RESPONSE.replace("DCC5", "DCC6");
	// the genuine card with alg HS256 instead of ES256, which is not in MTS1 (the issuer signature is then not valid either)
	private static final String HS256_GET_NEXT_DATA_RESPONSE = GET_NEXT_DATA_RESPONSE.replace("616C67654553323536", "616C67654853323536");

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

		assertThrows(InvalidCardMts7Exception.class, () -> processor.waitForVerify(0), "Expected card not to be trusted");
	}

	@Test
	public void testUnknownRootKeyWithOutdatedKeysIsNotInvalidCard() throws Exception {
		// the policy decides that our keys may be out of date: a problem with the verifier
		VerifyTrustChainMts7ProcessorFactory factory = new VerifyTrustChainMts7ProcessorFactory(ParticipantPublicKeys.newBuilder().build(), null,
				UnknownIssuerKeyPolicy.blameKeys(), executor);

		ExecutionException e = assertThrows(ExecutionException.class,
				() -> process(factory.create(), GET_NEXT_DATA_RESPONSE, SIGNATURE_RESPONSE).waitForVerify(0));
		OutdatedIssuerKeysException cause = assertInstanceOf(OutdatedIssuerKeysException.class, e.getCause());
		assertEquals(10, cause.getIssuerId());
	}

	@Test
	public void testUnknownRootKeyIsRejectedByDefault() throws Exception {
		VerifyTrustChainMts7ProcessorFactory factory = new VerifyTrustChainMts7ProcessorFactory(ParticipantPublicKeys.newBuilder().build(), executor);

		assertFalse(factory.isTrustUnknownRootKeys());
		UnknownIssuerKeyInvalidCardMts7Exception e = assertThrows(UnknownIssuerKeyInvalidCardMts7Exception.class,
				() -> process(factory.create(), GET_NEXT_DATA_RESPONSE, SIGNATURE_RESPONSE).waitForVerify(0));
		assertEquals(10, e.getIssuerId());
		assertEquals("10:20230213", e.getKeyId());
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

		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> process(factory.create(), GET_NEXT_DATA_RESPONSE, OTHER_SIGNATURE_RESPONSE).waitForVerify(0));
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

		TrustChainInvalidCardMts7Exception e = assertThrows(TrustChainInvalidCardMts7Exception.class,
				() -> process(factory.create(), ByteArrayHexStringConverter.toHexString(getNextDataResponse), SIGNATURE_RESPONSE).waitForVerify(0));

		// the key is known, so the issuer signature is not valid
		assertFalse(e instanceof UnknownIssuerKeyInvalidCardMts7Exception);
	}

	@Test
	public void testKnownUnsupportedRootKeyIsNotInvalidCard() throws Exception {
		// a problem with the verifier, also with the option: the key is known, so it is not an unknown key, and the card is not to blame
		VerifyTrustChainMts7ProcessorFactory factory = new VerifyTrustChainMts7ProcessorFactory(unsupportedRootKey(), null, true, executor);

		ExecutionException e = assertThrows(ExecutionException.class,
				() -> process(factory.create(), GET_NEXT_DATA_RESPONSE, SIGNATURE_RESPONSE).waitForVerify(0));

		assertInstanceOf(UnableToConstructIssuerKeyException.class, e.getCause());
		assertTrue(e.getCause().getMessage().contains("not supported"), e.getCause().getMessage());
	}

	@Test
	public void testMalformedMobileTicketBundleIsInvalidCard() throws Exception {
		InvalidCardMts7Exception e = assertThrows(InvalidCardMts7Exception.class,
				() -> process(processorFactory.create(), "0102039000", SIGNATURE_RESPONSE).waitForVerify(0));

		assertFalse(e instanceof KeyPairInvalidCardMts7Exception);
		assertFalse(e instanceof TrustChainInvalidCardMts7Exception);
		assertInstanceOf(IOException.class, e.getCause());
	}

	@Test
	public void testIssuerKeyWhichCannotBeCreatedIsNotInvalidCard() throws Exception {
		// a problem with the verifier: the root key of the card is among the issuer keys, but it cannot be created
		VerifyTrustChainMts7ProcessorFactory factory = new VerifyTrustChainMts7ProcessorFactory(rootKey(new IssuerSignatureFactory() {
			@Override
			public IssuerPublicKey createIssuerPublicKey(long pid, MtbJwkPublic jwkPublic) throws UnableToConstructIssuerKeyException {
				throw new UnableToConstructIssuerKeyException("Broken");
			}
		}), executor);

		ExecutionException e = assertThrows(ExecutionException.class,
				() -> process(factory.create(), GET_NEXT_DATA_RESPONSE, SIGNATURE_RESPONSE).waitForVerify(0));

		assertInstanceOf(UnableToConstructIssuerKeyException.class, e.getCause());
	}

	@Test
	public void testAlgorithmNotInTheSpecificationIsBlamedOnTheCardBeforeTheIssuerKey() throws Exception {
		// the issuer key of the card is known but cannot be used (the verifier), but the card is not as in the specification, so it is to blame
		IssuerSignatureFactory broken = new IssuerSignatureFactory() {
			@Override
			public IssuerPublicKey createIssuerPublicKey(long pid, MtbJwkPublic jwkPublic) throws UnableToConstructIssuerKeyException {
				throw new UnableToConstructIssuerKeyException("Broken");
			}
		};
		for (ParticipantPublicKeys keys : new ParticipantPublicKeys[] { unsupportedRootKey(), rootKey(broken) }) {
			VerifyTrustChainMts7ProcessorFactory factory = new VerifyTrustChainMts7ProcessorFactory(keys, executor);

			InvalidCardMts7Exception e = assertThrows(InvalidCardMts7Exception.class,
					() -> process(factory.create(), HS256_GET_NEXT_DATA_RESPONSE, SIGNATURE_RESPONSE).waitForVerify(0));
			assertEquals(InvalidCardMts7Exception.class, e.getClass());
			assertEquals("Issuer signature algorithm HS256 is not ES256 or RS256", e.getMessage());

			// as in the specification, so the problem is with the verifier
			ExecutionException ours = assertThrows(ExecutionException.class,
					() -> process(factory.create(), GET_NEXT_DATA_RESPONSE, SIGNATURE_RESPONSE).waitForVerify(0));
			assertInstanceOf(UnableToConstructIssuerKeyException.class, ours.getCause());
		}
	}

	@Test
	public void testUnavailableSignatureAlgorithmIsNotInvalidCard() throws Exception {
		// a problem with the verifier: the security provider does not have the signature algorithm of the card
		Provider empty = new Provider("Empty", "1.0", "Without algorithms") {
			private static final long serialVersionUID = 1L;
		};
		VerifyTrustChainMts7ProcessorFactory factory = new VerifyTrustChainMts7ProcessorFactory(participantPublicKeys, false, new IccPublicKeyFactory(empty),
				new Mts7CardEnricher(), new CBORMapper(), new ThumbprintFactory(null), executor);

		ExecutionException e = assertThrows(ExecutionException.class,
				() -> process(factory.create(), GET_NEXT_DATA_RESPONSE, SIGNATURE_RESPONSE).waitForVerify(0));

		assertInstanceOf(NoSuchAlgorithmMts7Exception.class, e.getCause());
	}

	// the root key of the card is among the issuer keys, but its type is not supported
	private static ParticipantPublicKeys unsupportedRootKey() throws Exception {
		return rootKey(new IssuerSignatureFactory() {
			@Override
			public IssuerPublicKey createIssuerPublicKey(long pid, MtbJwkPublic jwkPublic) {
				return null;
			}
		});
	}

	// the root key of the card is among the issuer keys, and is created by the factory
	private static ParticipantPublicKeys rootKey(IssuerSignatureFactory factory) {
		Map<String, ParticipantPublicKeys.IssuerKey> keys = new HashMap<>();
		keys.put("10:20230213", new ParticipantPublicKeys.IssuerKey(new MtbJwkPublic().kty("EC").kid("10:20230213")));

		Map<Long, ParticipantPublicKeys.Issuer> issuers = new HashMap<>();
		issuers.put(10L, new ParticipantPublicKeys.Issuer("Ten", 10L, keys, factory));

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
