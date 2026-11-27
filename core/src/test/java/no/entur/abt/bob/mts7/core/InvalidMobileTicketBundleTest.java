package no.entur.abt.bob.mts7.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.api.pm.model.MtbJwkPublic;
import no.entur.abt.bob.api.pm.model.ParticipantMetadata;
import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.api.ReaderMts7Exception;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;
import no.entur.abt.bob.mts7.mtb.IssuerSignatureProtectedHeader;
import no.entur.abt.bob.mts7.test.mtb.InvalidMobileTicketBundles;

/**
 * Verify the deliberately invalid Mobile Ticket Bundles (see {@linkplain InvalidMobileTicketBundles}) with the card factories: each is either verified, or
 * rejected as a problem on the card side, with the expected exception.
 */

public class InvalidMobileTicketBundleTest {

	// the cases where only alg, the algorithm of the issuer signature, is missing or not as in MTS1
	private static final Set<String> ISSUER_SIGNATURE_ALGORITHM_ONLY = new HashSet<>(Arrays.asList("no alg", "empty alg", "unknown alg"));

	private static InvalidMobileTicketBundles bundles;
	private static ParticipantPublicKeys issuers;

	@BeforeAll
	public static void load() throws Exception {
		bundles = InvalidMobileTicketBundles.load();

		InvalidMobileTicketBundles.Issuer issuer = bundles.issuer;
		ParticipantMetadata participant = new ParticipantMetadata();
		participant.setPid(issuer.pid);
		participant.setOrganisationName("Test issuer");
		participant.setMtbPublicKeys(Arrays.asList(new MtbJwkPublic().kty(issuer.kty).kid(issuer.kid).crv(issuer.crv).x(issuer.x).y(issuer.y)));
		issuers = ParticipantPublicKeys.newBuilder().withParticipant(participant).build();
	}

	@TestFactory
	public Stream<DynamicTest> testTrustChain() throws Exception {
		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(issuers);

		return bundles.cases.stream().map(c -> DynamicTest.dynamicTest(c.name, () -> assertOutcome(c.trustChain, true, () -> factory.create(payloads(c)))));
	}

	@TestFactory
	public Stream<DynamicTest> testKeyPair() throws Exception {
		VerifyKeyPairMts7CardFactory factory = new VerifyKeyPairMts7CardFactory();

		return bundles.cases.stream().map(c -> DynamicTest.dynamicTest(c.name, () -> assertOutcome(c.keyPair, false, () -> factory.create(payloads(c)))));
	}

	@TestFactory
	public Stream<DynamicTest> testLenient() throws Exception {
		LenientMts7CardFactory factory = new LenientMts7CardFactory();

		// never throws, and verifies the key pair as far as it can, also if the select application response is not valid (those cases have a valid bundle),
		// or the algorithm of the issuer signature is not (it says nothing about the key of the card)
		return bundles.cases.stream().map(c -> DynamicTest.dynamicTest(c.name, () -> {
			Mts7Card card = factory.create(payloads(c));

			boolean selectApplicationResponseOnly = c.selectApplicationResponse != null;
			boolean issuerSignatureAlgorithmOnly = ISSUER_SIGNATURE_ALGORITHM_ONLY.contains(c.name);
			assertEquals(selectApplicationResponseOnly || issuerSignatureAlgorithmOnly || InvalidMobileTicketBundles.VERIFIED.equals(c.keyPair),
					card.isVerifiedPrivateKeyPresent());
			assertFalse(card.isVerifiedTrustChain());
		}));
	}

	@Test
	public void testThumbprintWhichCannotBeCreatedIsNotInvalidCard() throws Exception {
		// the public key of a valid card can be created, so a thumbprint which cannot is a problem with the verifier
		ThumbprintFactory thumbprintFactory = failingThumbprintFactory();
		Mts7ApduPayloads payloads = payloads(bundle("valid"));

		assertThrows(UnableToConstructThumbprintKeyException.class,
				() -> new VerifyMts7CardFactory(issuers, new IccPublicKeyFactory(), new Mts7CardEnricher(), new CBORMapper(), thumbprintFactory)
						.create(payloads));
		assertThrows(UnableToConstructThumbprintKeyException.class,
				() -> new VerifyKeyPairMts7CardFactory(new IccPublicKeyFactory(), new Mts7CardEnricher(), new CBORMapper(), thumbprintFactory)
						.create(payloads));
	}

	@Test
	public void testThumbprintOfAnInvalidKeyIsInvalidCard() throws Exception {
		// a thumbprint which cannot be created because of the public key of the card is a problem on the card side (not expected after the key itself could
		// be created)
		ThumbprintFactory thumbprintFactory = cardSideFailingThumbprintFactory();
		Mts7ApduPayloads payloads = payloads(bundle("valid"));

		assertThrows(NonCompliantIccKeyInvalidCardMts7Exception.class,
				() -> new VerifyMts7CardFactory(issuers, new IccPublicKeyFactory(), new Mts7CardEnricher(), new CBORMapper(), thumbprintFactory)
						.create(payloads));
		assertThrows(NonCompliantIccKeyInvalidCardMts7Exception.class,
				() -> new VerifyKeyPairMts7CardFactory(new IccPublicKeyFactory(), new Mts7CardEnricher(), new CBORMapper(), thumbprintFactory)
						.create(payloads));
	}

	@Test
	public void testCardSideProblemIsReportedBeforeTheThumbprint() throws Exception {
		// without a token public key, neither the public key of the card nor the thumbprint can be created: the card is to blame
		ThumbprintFactory thumbprintFactory = failingThumbprintFactory();
		Mts7ApduPayloads payloads = payloads(bundle("no tpk"));

		assertThrows(InvalidCardMts7Exception.class,
				() -> new VerifyMts7CardFactory(issuers, new IccPublicKeyFactory(), new Mts7CardEnricher(), new CBORMapper(), thumbprintFactory)
						.create(payloads));
		assertThrows(InvalidCardMts7Exception.class,
				() -> new VerifyKeyPairMts7CardFactory(new IccPublicKeyFactory(), new Mts7CardEnricher(), new CBORMapper(), thumbprintFactory)
						.create(payloads));
	}

	private interface Verification {
		Mts7Card verify() throws Exception;
	}

	private static void assertOutcome(String expected, boolean trustChain, Verification verification) throws Exception {
		if (InvalidMobileTicketBundles.VERIFIED.equals(expected)) {
			Mts7Card card = verification.verify();

			assertTrue(card.isVerifiedPrivateKeyPresent());
			assertEquals(trustChain, card.isVerifiedTrustChain());
			assertTrue(card.hasThumprint());
		} else {
			// a problem on the card side, or with the reader, never ours
			Exception e = assertThrows(Exception.class, verification::verify);

			assertEquals(expected, e.getClass().getSimpleName(), e.getMessage());
			assertTrue(e instanceof InvalidCardMts7Exception || e instanceof ReaderMts7Exception, e.getClass().getName());
		}
	}

	private static Mts7ApduPayloads payloads(InvalidMobileTicketBundles.Case c) {
		Mts7ApduPayloads payloads = new Mts7ApduPayloads();
		payloads.setSelectApplicationOutput(InvalidMobileTicketBundles.withoutStatusWord(bundles.selectApplicationResponseApdu(c)));
		payloads.setGetDataOutput(InvalidMobileTicketBundles.withoutStatusWord(c.getDataResponseApdu()));
		if (c.applicationRelatedDataResponse != null) {
			payloads.setApplicationRelatedDataOutput(InvalidMobileTicketBundles.withoutStatusWord(c.applicationRelatedDataResponseApdu()));
		}
		payloads.setInternalAuthenticateInput(bundles.challengeBytes());
		payloads.setInternalAuthenticateOutput(InvalidMobileTicketBundles.withoutStatusWord(bundles.internalAuthenticateResponseApdu()));
		return payloads;
	}

	// fails as with a problem with the verifier (the digest algorithm is checked when the factory is created, so this is not expected to happen)
	private static ThumbprintFactory failingThumbprintFactory() throws Exception {
		return new ThumbprintFactory(null) {
			@Override
			public byte[] create(IssuerSignatureProtectedHeader header) throws UnableToConstructThumbprintKeyException {
				throw new UnableToConstructThumbprintKeyException("Broken");
			}
		};
	}

	// fails as with a problem with the public key of the card
	private static ThumbprintFactory cardSideFailingThumbprintFactory() throws Exception {
		return new ThumbprintFactory(null) {
			@Override
			public byte[] create(IssuerSignatureProtectedHeader header) throws NonCompliantIccKeyInvalidCardMts7Exception {
				throw new NonCompliantIccKeyInvalidCardMts7Exception("Broken");
			}
		};
	}

	private static InvalidMobileTicketBundles.Case bundle(String name) {
		return bundles.cases.stream().filter(c -> c.name.equals(name)).findFirst().orElseThrow(() -> new IllegalArgumentException(name));
	}

}
