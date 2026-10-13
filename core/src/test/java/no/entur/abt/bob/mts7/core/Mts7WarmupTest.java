package no.entur.abt.bob.mts7.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.api.pm.model.ParticipantMetadata;
import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class Mts7WarmupTest {

	private static byte[] fromResponseApdu(String hex) {
		byte[] response = ByteArrayHexStringConverter.hexStringToByteArray(hex);

		byte[] payload = new byte[response.length - 2];
		System.arraycopy(response, 0, payload, 0, payload.length);
		return payload;
	}

	private Mts7ApduPayloads payloads() {
		Mts7ApduPayloads payloads = new Mts7ApduPayloads();
		payloads.setSelectApplicationOutput(fromResponseApdu("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000"));
		payloads.setGetDataOutput(fromResponseApdu(
				"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000"));
		payloads.setInternalAuthenticateInput(ByteArrayHexStringConverter.hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000000"));
		payloads.setInternalAuthenticateOutput(fromResponseApdu(
				"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000"));
		return payloads;
	}

	@Test
	public void testWarmUpDoesNotAffectTheResult() throws Exception {
		InputStream is = getClass().getResourceAsStream("/participantMetadata.json");
		List<ParticipantMetadata> participantMetadata = Arrays.asList(new ObjectMapper().readValue(is, ParticipantMetadata[].class));
		assertFalse(participantMetadata.isEmpty());

		ParticipantPublicKeys participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();
		assertTrue(participantPublicKeys.warmUp().isEmpty());

		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(participantPublicKeys);

		// harmless to repeat, and to run on several threads
		factory.warmUp();
		factory.warmUp();

		Mts7Card card = factory.create(payloads());

		assertTrue(card.isVerifiedPrivateKeyPresent());
		assertTrue(card.isVerifiedTrustChain());
		assertEquals("0000175F96B61D", ByteArrayHexStringConverter.toHexString(card.getSerial()));
	}

	@Test
	public void testWarmUpOtherFactories() throws Exception {
		VerifyKeyPairMts7CardFactory keyPair = new VerifyKeyPairMts7CardFactory();
		keyPair.warmUp();
		assertTrue(keyPair.create(payloads()).isVerifiedPrivateKeyPresent());

		LenientMts7CardFactory lenient = new LenientMts7CardFactory();
		lenient.warmUp();
		assertTrue(lenient.create(payloads()).isVerifiedPrivateKeyPresent());
	}

	@Test
	public void testSampleCardCanBeParsed() throws Exception {
		// warming up never fails, so this is the only way to find out that the sample is not valid
		Mts7Card card = Mts7Warmup.parseSampleCard(new CBORMapper(), new Mts7CardEnricher());

		assertEquals("0000175F96B61D", ByteArrayHexStringConverter.toHexString(card.getSerial()));
	}

}
