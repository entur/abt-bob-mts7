package no.entur.abt.bob.mts7.reader.processor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.api.pm.model.MtbJwkPublic;
import no.entur.abt.bob.api.pm.model.ParticipantMetadata;
import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.api.ReaderMts7Exception;
import no.entur.abt.bob.mts7.api.apdu.CommandAPDU;
import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.core.Mts7CardEnricher;
import no.entur.abt.bob.mts7.core.NonCompliantIccKeyInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.UnableToConstructThumbprintKeyException;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;
import no.entur.abt.bob.mts7.mtb.IssuerSignatureProtectedHeader;
import no.entur.abt.bob.mts7.test.mtb.InvalidMobileTicketBundles;

/**
 * Verify the deliberately invalid Mobile Ticket Bundles (see {@linkplain InvalidMobileTicketBundles}) with the processors: each is either verified, or rejected
 * as a problem on the card side, with the expected exception (not wrapped in an ExecutionException, which is for problems with the verifier).
 */

public class InvalidMobileTicketBundleProcessorTest {

	private static InvalidMobileTicketBundles bundles;
	private static ParticipantPublicKeys issuers;
	private static ExecutorService executor;

	@BeforeAll
	public static void load() throws Exception {
		bundles = InvalidMobileTicketBundles.load();

		InvalidMobileTicketBundles.Issuer issuer = bundles.issuer;
		ParticipantMetadata participant = new ParticipantMetadata();
		participant.setPid(issuer.pid);
		participant.setOrganisationName("Test issuer");
		participant.setMtbPublicKeys(Arrays.asList(new MtbJwkPublic().kty(issuer.kty).kid(issuer.kid).crv(issuer.crv).x(issuer.x).y(issuer.y)));
		issuers = ParticipantPublicKeys.newBuilder().withParticipant(participant).build();

		executor = Executors.newCachedThreadPool();
	}

	@AfterAll
	public static void shutdown() {
		executor.shutdownNow();
	}

	@TestFactory
	public Stream<DynamicTest> testTrustChain() throws Exception {
		VerifyTrustChainMts7ProcessorFactory factory = new VerifyTrustChainMts7ProcessorFactory(issuers, executor);

		return bundles.cases.stream().map(c -> DynamicTest.dynamicTest(c.name, () -> assertOutcome(c.trustChain, true, () -> process(factory.create(), c))));
	}

	@TestFactory
	public Stream<DynamicTest> testKeyPair() throws Exception {
		VerifyKeyPairMts7ProcessorFactory factory = new VerifyKeyPairMts7ProcessorFactory(executor);

		return bundles.cases.stream().map(c -> DynamicTest.dynamicTest(c.name, () -> assertOutcome(c.keyPair, false, () -> process(factory.create(), c))));
	}

	@Test
	public void testThumbprintWhichCannotBeCreatedIsNotInvalidCard() throws Exception {
		// the public key of a valid card can be created, so a thumbprint which cannot is a problem with the verifier
		ThumbprintFactory thumbprintFactory = failingThumbprintFactory();
		InvalidMobileTicketBundles.Case valid = bundle("valid");

		ExecutionException trustChain = assertThrows(ExecutionException.class, () -> process(new VerifyTrustChainMts7ProcessorFactory(issuers,
				new IccPublicKeyFactory(), new Mts7CardEnricher(), new CBORMapper(), thumbprintFactory, executor).create(), valid));
		assertInstanceOf(UnableToConstructThumbprintKeyException.class, trustChain.getCause());

		ExecutionException keyPair = assertThrows(ExecutionException.class,
				() -> process(
						new VerifyKeyPairMts7ProcessorFactory(new IccPublicKeyFactory(), new Mts7CardEnricher(), new CBORMapper(), thumbprintFactory, executor)
								.create(),
						valid));
		assertInstanceOf(UnableToConstructThumbprintKeyException.class, keyPair.getCause());
	}

	@Test
	public void testThumbprintOfAnInvalidKeyIsInvalidCard() throws Exception {
		// a thumbprint which cannot be created because of the public key of the card is a problem on the card side (not expected after the key itself could
		// be created)
		ThumbprintFactory thumbprintFactory = cardSideFailingThumbprintFactory();
		InvalidMobileTicketBundles.Case valid = bundle("valid");

		assertThrows(NonCompliantIccKeyInvalidCardMts7Exception.class, () -> process(new VerifyTrustChainMts7ProcessorFactory(issuers,
				new IccPublicKeyFactory(), new Mts7CardEnricher(), new CBORMapper(), thumbprintFactory, executor).create(), valid));
		assertThrows(NonCompliantIccKeyInvalidCardMts7Exception.class,
				() -> process(
						new VerifyKeyPairMts7ProcessorFactory(new IccPublicKeyFactory(), new Mts7CardEnricher(), new CBORMapper(), thumbprintFactory, executor)
								.create(),
						valid));
	}

	@Test
	public void testCardSideProblemIsReportedBeforeTheThumbprint() throws Exception {
		// without a token public key, neither the public key of the card nor the thumbprint can be created: the card is to blame
		ThumbprintFactory thumbprintFactory = failingThumbprintFactory();
		InvalidMobileTicketBundles.Case noTpk = bundle("no tpk");

		assertThrows(InvalidCardMts7Exception.class, () -> process(new VerifyTrustChainMts7ProcessorFactory(issuers, new IccPublicKeyFactory(),
				new Mts7CardEnricher(), new CBORMapper(), thumbprintFactory, executor).create(), noTpk));
		assertThrows(InvalidCardMts7Exception.class,
				() -> process(
						new VerifyKeyPairMts7ProcessorFactory(new IccPublicKeyFactory(), new Mts7CardEnricher(), new CBORMapper(), thumbprintFactory, executor)
								.create(),
						noTpk));
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

	private static Mts7Card process(Mts7Processor processor, InvalidMobileTicketBundles.Case c) throws Exception {
		processor.onSelectApplicationResponseApdu(bundles.selectApplicationResponseApdu(c));
		if (c.applicationRelatedDataResponse != null) {
			// before the MTB, as the reader sends it
			processor.onApplicationRelatedDataResponseApdu(c.applicationRelatedDataResponseApdu());
		}
		processor.onGetDataResponseApdu(c.getDataResponseApdu());
		processor.onInternalAuthenticateApdu(new CommandAPDU(0, 0, 0, 0, bundles.challengeBytes()).getBytes(), bundles.internalAuthenticateResponseApdu());
		processor.run();
		return processor.waitForVerify(0);
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
