package no.entur.abt.bob.mts7.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

import no.entur.abt.bob.api.pm.model.MtbJwkPublic;
import no.entur.abt.bob.api.pm.model.ParticipantMetadata;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.IssuerPublicKey;
import no.entur.abt.bob.mts7.core.pki.IssuerSignatureFactory;
import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;
import no.entur.abt.bob.mts7.core.pki.jws.ParticipantMetadataJwsParser;
import no.entur.abt.bob.mts7.core.pki.jws.ParticipantMetadataJwsVerifier;
import no.entur.abt.bob.mts7.core.pki.jws.VerifiedParticipantMetadata;
import no.entur.abt.bob.mts7.core.pki.jws.VerifiedParticipantMetadataFactory;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class VerifyMts7CardFactoryTest {

	// the responses of a genuine card (with status words), the challenge being 32 zero bytes; its issuer is participant 10, key 10:20230213
	private static final String SELECT_APPLICATION_RESPONSE = "64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000";
	private static final String GET_NEXT_DATA_RESPONSE = "A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000";
	private static final String SIGNATURE_RESPONSE = "DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000";
	// as from a cloned card, which does not have the private key
	private static final String OTHER_SIGNATURE_RESPONSE = SIGNATURE_RESPONSE.replace("DCC5", "DCC6");
	// the genuine card with alg HS256 instead of ES256, which is not in MTS1 (the issuer signature is then not valid either)
	private static final String HS256_GET_NEXT_DATA_RESPONSE = GET_NEXT_DATA_RESPONSE.replace("616C67654553323536", "616C67654853323536");

	@Test
	public void testHelpersCanBeSharedWithOtherFactories() throws Exception {
		IccPublicKeyFactory iccPublicKeyFactory = new IccPublicKeyFactory();
		Mts7CardEnricher enricher = new Mts7CardEnricher();
		CBORMapper cborMapper = new CBORMapper();
		ThumbprintFactory thumbprintFactory = new ThumbprintFactory(null);

		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(ParticipantPublicKeys.newBuilder().build(), iccPublicKeyFactory, enricher, cborMapper,
				thumbprintFactory);

		assertSame(iccPublicKeyFactory, factory.getIccPublicKeyFactory());
		assertSame(enricher, factory.getEnricher());
		assertSame(cborMapper, factory.getCborMapper());
		assertSame(thumbprintFactory, factory.getThumbprintFactory());
	}

	@Test
	public void test() throws Exception {

		ObjectMapper mapper = new ObjectMapper();

		InputStream is = getClass().getResourceAsStream("/participantMetadata.json");

		List<ParticipantMetadata> participantMetadata = Arrays.asList(mapper.readValue(is, ParticipantMetadata[].class));
		assertFalse(participantMetadata.isEmpty());

		ParticipantPublicKeys participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();

		byte[] challenge = ByteArrayHexStringConverter.hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000000");
		byte[] selectApplicationResponse = ByteArrayHexStringConverter
				.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");
		byte[] getNextDataResponse = ByteArrayHexStringConverter.hexStringToByteArray(
				"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000");
		byte[] signatureResponse = ByteArrayHexStringConverter.hexStringToByteArray(
				"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");

		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(participantPublicKeys);

		Mts7ApduPayloads binaryCard = new Mts7ApduPayloads();
		binaryCard.setSelectApplicationOutput(fromResponseApdu(selectApplicationResponse));
		binaryCard.setGetDataOutput(fromResponseApdu(getNextDataResponse));
		binaryCard.setInternalAuthenticateInput(challenge);
		binaryCard.setInternalAuthenticateOutput(fromResponseApdu(signatureResponse));

		Mts7Card card = factory.create(binaryCard);

		assertTrue(card.isVerifiedPrivateKeyPresent());
		assertTrue(card.isVerifiedTrustChain());

		assertEquals("0000175F96B61D", ByteArrayHexStringConverter.toHexString(card.getSerial()));
	}

	@Test
	public void testUnknownRootKeyIsRejectedByDefault() throws Exception {
		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(ParticipantPublicKeys.newBuilder().build());

		assertFalse(factory.isTrustUnknownRootKeys());
		UnknownIssuerKeyInvalidCardMts7Exception e = assertThrows(UnknownIssuerKeyInvalidCardMts7Exception.class,
				() -> factory.create(card(SIGNATURE_RESPONSE)));
		assertEquals(10, e.getIssuerId());
		assertEquals("10:20230213", e.getKeyId());
		assertFalse(e.getResult().isVerifiedTrustChain());
	}

	@Test
	public void testUnknownRootKeyIsTrustedWithOption() throws Exception {
		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(ParticipantPublicKeys.newBuilder().build(), null, true);

		Mts7Card card = factory.create(card(SIGNATURE_RESPONSE));

		assertTrue(factory.isTrustUnknownRootKeys());
		assertTrue(card.isVerifiedPrivateKeyPresent());
		assertFalse(card.isVerifiedTrustChain());
		assertTrue(card.hasThumprint());
		assertEquals("0000175F96B61D", ByteArrayHexStringConverter.toHexString(card.getSerial()));
	}

	@Test
	public void testUnknownRootKeyWithoutPrivateKeyIsRejectedWithOption() throws Exception {
		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(ParticipantPublicKeys.newBuilder().build(), null, true);

		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> factory.create(card(OTHER_SIGNATURE_RESPONSE)));
	}

	@Test
	public void testKnownRootKeyIsVerifiedWithOption() throws Exception {
		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(participantPublicKeys(), null, true);

		Mts7Card card = factory.create(card(SIGNATURE_RESPONSE));

		assertTrue(card.isVerifiedPrivateKeyPresent());
		assertTrue(card.isVerifiedTrustChain());
	}

	@Test
	public void testCardNotSignedByKnownRootKeyIsRejectedWithOption() throws Exception {
		// the root key of the card is known, but it is another key than the one which signed the card certificate
		ECKey otherKey = new ECKeyGenerator(Curve.P_256).generate();
		MtbJwkPublic otherJwk = new MtbJwkPublic().kty("EC").kid("10:20230213").crv("P-256").x(otherKey.getX().toString()).y(otherKey.getY().toString());
		ParticipantMetadata issuer = new ParticipantMetadata().pid(10L).organisationName("Ten").mtbPublicKeys(List.of(otherJwk));
		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(ParticipantPublicKeys.newBuilder().withParticipants(List.of(issuer)).build(), null, true);

		TrustChainInvalidCardMts7Exception e = assertThrows(TrustChainInvalidCardMts7Exception.class, () -> factory.create(card(SIGNATURE_RESPONSE)));

		// the key is known, so the issuer signature is not valid
		assertFalse(e instanceof UnknownIssuerKeyInvalidCardMts7Exception);
		assertFalse(e.getResult().isVerifiedTrustChain());
	}

	@Test
	public void testCardWithoutPrivateKeyIsRejectedWithOption() throws Exception {
		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(participantPublicKeys(), null, true);

		KeyPairInvalidCardMts7Exception e = assertThrows(KeyPairInvalidCardMts7Exception.class, () -> factory.create(card(OTHER_SIGNATURE_RESPONSE)));

		assertTrue(e.getResult().isVerifiedTrustChain());
	}

	@Test
	public void testKnownUnsupportedRootKeyIsNotInvalidCard() throws Exception {
		// a problem on our side, also with the option: the key is known, so it is not an unknown key, and the card is not to blame
		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(unsupportedRootKey(), null, true);

		UnableToConstructIssuerKeyException e = assertThrows(UnableToConstructIssuerKeyException.class, () -> factory.create(card(SIGNATURE_RESPONSE)));

		assertTrue(e.getMessage().contains("not supported"), e.getMessage());
	}

	@Test
	public void testVerifiedParticipantMetadataJws() throws Exception {
		// from the signed participant metadata to a verified card
		VerifiedParticipantMetadataFactory metadataFactory = new VerifiedParticipantMetadataFactory(new ParticipantMetadataJwsParser(),
				new ParticipantMetadataJwsVerifier(JWKSet.parse(read("/samtrafiken-prod.json"))));

		// the signatures are valid from 2026-11-18T10:03:02Z until 2026-11-25T10:03:02Z
		VerifiedParticipantMetadata verified = metadataFactory.create(read("/participantMetadataJws.json"),
				Instant.parse("2026-11-20T00:00:00Z").toEpochMilli());

		ParticipantPublicKeys keys = ParticipantPublicKeys.newBuilder().withParticipants(verified.getParticipantMetadata()).build();
		assertTrue(keys.hasIssuerPublicKey(10L, "10:20230213"));

		Mts7Card card = new VerifyMts7CardFactory(keys).create(card(SIGNATURE_RESPONSE));

		assertTrue(card.isVerifiedPrivateKeyPresent());
		assertTrue(card.isVerifiedTrustChain());
		assertEquals("0000175F96B61D", ByteArrayHexStringConverter.toHexString(card.getSerial()));

		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> new VerifyMts7CardFactory(keys).create(card(OTHER_SIGNATURE_RESPONSE)));
	}

	@Test
	public void testAlgorithmNotInTheSpecificationIsBlamedOnTheCardBeforeTheIssuerKey() throws Exception {
		// the issuer key of the card is known but cannot be used (our side), but the card is not as in the specification, so it is to blame
		IssuerSignatureFactory broken = new IssuerSignatureFactory() {
			@Override
			public IssuerPublicKey createIssuerPublicKey(long pid, MtbJwkPublic jwkPublic) throws UnableToConstructIssuerKeyException {
				throw new UnableToConstructIssuerKeyException("Broken");
			}
		};
		for (ParticipantPublicKeys keys : new ParticipantPublicKeys[] { unsupportedRootKey(), rootKey(broken) }) {
			VerifyMts7CardFactory factory = new VerifyMts7CardFactory(keys);

			InvalidCardMts7Exception e = assertThrows(InvalidCardMts7Exception.class,
					() -> factory.create(card(HS256_GET_NEXT_DATA_RESPONSE, SIGNATURE_RESPONSE)));
			assertEquals(InvalidCardMts7Exception.class, e.getClass());
			assertEquals("Issuer signature algorithm HS256 is not ES256 or RS256", e.getMessage());

			// as in the specification, so the problem is on our side
			assertThrows(UnableToConstructIssuerKeyException.class, () -> factory.create(card(SIGNATURE_RESPONSE)));
		}
	}

	@Test
	public void testIssuerKeyWhichCannotBeCreatedIsNotInvalidCard() throws Exception {
		// a problem on our side: the root key of the card is among the issuer keys, but it cannot be created
		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(rootKey(new IssuerSignatureFactory() {
			@Override
			public IssuerPublicKey createIssuerPublicKey(long pid, MtbJwkPublic jwkPublic) throws UnableToConstructIssuerKeyException {
				throw new UnableToConstructIssuerKeyException("Broken");
			}
		}), null, true);

		assertThrows(UnableToConstructIssuerKeyException.class, () -> factory.create(card(SIGNATURE_RESPONSE)));
	}

	@Test
	public void testUnavailableSignatureAlgorithmIsNotInvalidCard() throws Exception {
		// a problem on our side: the security provider does not have the signature algorithm of the card
		Provider empty = new Provider("Empty", "1.0", "Without algorithms") {
			private static final long serialVersionUID = 1L;
		};
		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(participantPublicKeys(), new IccPublicKeyFactory(empty), new Mts7CardEnricher(),
				new CBORMapper(), new ThumbprintFactory(null));

		assertThrows(NoSuchAlgorithmException.class, () -> factory.create(card(SIGNATURE_RESPONSE)));
	}

	@Test
	public void testMalformedMobileTicketBundleIsInvalidCard() throws Exception {
		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(participantPublicKeys());

		Mts7ApduPayloads payloads = card(SIGNATURE_RESPONSE);
		payloads.setGetDataOutput(new byte[] { 0x01, 0x02, 0x03 });

		InvalidCardMts7Exception e = assertThrows(InvalidCardMts7Exception.class, () -> factory.create(payloads));

		assertFalse(e instanceof KeyPairInvalidCardMts7Exception);
		assertInstanceOf(IOException.class, e.getCause());
		// the card as far as it was read
		assertEquals("0000175F96B61D", ByteArrayHexStringConverter.toHexString(e.getResult().getSerial()));
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

	private String read(String resource) throws Exception {
		try (InputStream is = getClass().getResourceAsStream(resource)) {
			return new String(is.readAllBytes(), StandardCharsets.UTF_8);
		}
	}

	private ParticipantPublicKeys participantPublicKeys() throws Exception {
		try (InputStream is = getClass().getResourceAsStream("/participantMetadata.json")) {
			List<ParticipantMetadata> participantMetadata = Arrays.asList(new ObjectMapper().readValue(is, ParticipantMetadata[].class));
			return ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();
		}
	}

	private Mts7ApduPayloads card(String signatureResponse) {
		return card(GET_NEXT_DATA_RESPONSE, signatureResponse);
	}

	private Mts7ApduPayloads card(String getNextDataResponse, String signatureResponse) {
		Mts7ApduPayloads card = new Mts7ApduPayloads();
		card.setSelectApplicationOutput(fromResponseApdu(ByteArrayHexStringConverter.hexStringToByteArray(SELECT_APPLICATION_RESPONSE)));
		card.setGetDataOutput(fromResponseApdu(ByteArrayHexStringConverter.hexStringToByteArray(getNextDataResponse)));
		card.setInternalAuthenticateInput(new byte[32]);
		card.setInternalAuthenticateOutput(fromResponseApdu(ByteArrayHexStringConverter.hexStringToByteArray(signatureResponse)));
		return card;
	}

	public byte[] fromResponseApdu(byte[] response) {
		byte[] payload = new byte[response.length - 2];
		System.arraycopy(response, 0, payload, 0, payload.length);
		return payload;
	}

}
