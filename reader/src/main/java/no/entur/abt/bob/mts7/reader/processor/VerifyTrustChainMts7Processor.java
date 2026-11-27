package no.entur.abt.bob.mts7.reader.processor;

import java.io.IOException;
import java.util.concurrent.Executor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.KeyPairInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.Mts7CardEnricher;
import no.entur.abt.bob.mts7.core.UnableToConstructIssuerKeyException;
import no.entur.abt.bob.mts7.core.UnknownIssuerKeyInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.pki.IccPublicKey;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyBuilder;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.IssuerPublicKey;
import no.entur.abt.bob.mts7.core.pki.Mts1Algorithms;
import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;
import no.entur.abt.bob.mts7.mtb.IssuerSignatureProtectedHeader;
import no.entur.abt.bob.mts7.mtb.MobileTicketBundle;
import no.entur.abt.bob.mts7.mtb.MobileTicketBundleParser;

/**
 * 
 * Processor for MTS7 card integrity check which includes the root certificates.
 * <p>
 * With <code>trustUnknownRootKeys</code>, a card whose root key is not among the issuer keys is accepted if it proves that it has the private key; see
 * {@linkplain VerifyTrustChainMts7ProcessorFactory}.
 * <p>
 * A processor is for one card only.
 * 
 */

public class VerifyTrustChainMts7Processor extends AbstractMts7Processor {

	private static final Logger LOGGER = LoggerFactory.getLogger(VerifyTrustChainMts7Processor.class);

	protected final ParticipantPublicKeys participantPublicKeys;
	protected final boolean trustUnknownRootKeys;
	protected final IccPublicKeyFactory iccSignatureFactory;
	protected final CBORMapper cborMapper;
	protected final MobileTicketBundleParser mobileTicketBundleParser;
	protected final Mts7CardEnricher enricher;

	protected final ThumbprintFactory thumbprintFactory;

	public VerifyTrustChainMts7Processor(ParticipantPublicKeys participantPublicKeys, IccPublicKeyFactory factory, Mts7CardEnricher enricher,
			CBORMapper cborMapper, ThumbprintFactory thumbprintFactory, Executor executor) {
		this(participantPublicKeys, false, factory, enricher, cborMapper, thumbprintFactory, executor);
	}

	public VerifyTrustChainMts7Processor(ParticipantPublicKeys participantPublicKeys, boolean trustUnknownRootKeys, IccPublicKeyFactory factory,
			Mts7CardEnricher enricher, CBORMapper cborMapper, ThumbprintFactory thumbprintFactory, Executor executor) {
		super(executor);

		this.participantPublicKeys = participantPublicKeys;
		this.trustUnknownRootKeys = trustUnknownRootKeys;
		this.iccSignatureFactory = factory;

		this.cborMapper = cborMapper;
		this.mobileTicketBundleParser = new MobileTicketBundleParser(cborMapper);
		this.enricher = enricher;
		this.thumbprintFactory = thumbprintFactory;
	}

	@Override
	protected void process() throws Exception {
		if (!awaitInput(() -> selectApplicationResponsePayload != null)) {
			return;
		}

		byte[] selectApplicationResponse = selectApplicationResponsePayload;
		updateResult(card -> enricher.enrichSelectApplicationResponsePayload(card, selectApplicationResponse));

		LOGGER.info("Processed 'select application' response");

		if (!awaitInput(() -> getDataResponsePayload != null)) {
			return;
		}

		MobileTicketBundle mobileTicketBundle;
		try {
			mobileTicketBundle = mobileTicketBundleParser.parse(getDataResponsePayload);
		} catch (IOException e) {
			throw new InvalidCardMts7Exception("Unable to parse the Mobile Ticket Bundle", e);
		}

		IssuerSignatureProtectedHeader header = mobileTicketBundle.getIssuerSignatureProtectedHeader();
		if (header == null) {
			throw new InvalidCardMts7Exception("Missing Issuer Signature Protected Header");
		}

		// MTS1 requires alg, the algorithm of the issuer signature, and has two. Checked before anything else in the header, so that a card which is
		// not as in the specification is to blame, whatever happens on our side with the issuer key.
		if (!Mts1Algorithms.isIssuerSignatureAlgorithm(header.getAlg())) {
			throw new InvalidCardMts7Exception(
					"Issuer signature algorithm " + header.getAlg() + " is not " + Mts1Algorithms.ES256 + " or " + Mts1Algorithms.RS256);
		}

		// note here what kind of algorithm the card uses: EC and RSA do not encode the input to the internal authenticate function in the same way. It
		// follows from the type of the public key of the card, not from alg in the header, which is the algorithm of the issuer signature.

		setIccKeyAlgorithm(Mts1Algorithms.getTokenAlgorithm(header.getTpk()));

		long iid;
		try {
			iid = Long.parseLong(header.getIid());
		} catch (NumberFormatException e) {
			throw new InvalidCardMts7Exception("Invalid issuer id " + header.getIid(), e);
		}

		IccPublicKey iccPublicKey;

		IssuerPublicKey issuerPublicKey = participantPublicKeys.getIssuerPublicKey(iid, header.getKid());
		if (issuerPublicKey != null) {
			IccPublicKeyBuilder iccPublicKeyBuilder = new IccPublicKeyBuilder(iccSignatureFactory);
			for (byte[] value : mobileTicketBundle.getSignedElements()) {
				iccPublicKeyBuilder.withSignedData(value, 0, value.length);
			}
			iccPublicKeyBuilder.withSignature(mobileTicketBundle.getSignature());
			iccPublicKeyBuilder.withIssuerSignatureProtectedHeader(header);
			iccPublicKeyBuilder.withIssuerPublicKey(issuerPublicKey);

			iccPublicKey = iccPublicKeyBuilder.build();

			LOGGER.info("Verified ICC trust chain");

			updateResult(card -> card.setVerifiedTrustChain(true));
		} else if (participantPublicKeys.hasIssuerPublicKey(iid, header.getKid())) {
			// a key which is known, but which we cannot use, is not an unknown key, and not the fault of the card
			throw new UnableToConstructIssuerKeyException("Issuer public key " + header.getKid() + " of participant " + iid + " is not supported");
		} else if (trustUnknownRootKeys) {
			// The issuer key is unknown, so the issuer signature of the card certificate cannot be checked. Take the public key of the card from the
			// certificate as it is, and only check that the card has the private key for it, as VerifyKeyPairMts7Processor does. This does not say
			// who issued the card, so the trust chain stays not verified.
			iccPublicKey = iccSignatureFactory.create(header);
		} else {
			throw new UnknownIssuerKeyInvalidCardMts7Exception(iid, header.getKid());
		}

		// from the same token public key as the public key of the card, which could be created, so a problem here is expected to be on our side
		byte[] thumbprint = thumbprintFactory.create(header);
		updateResult(card -> card.setThumbprint(thumbprint));

		LOGGER.info("Processed 'get (next) data' response");

		// most of the waiting is here
		if (!awaitInput(this::isInternalAuthenticateAvailable)) {
			return;
		}

		// the command and the response of the same call
		InternalAuthenticate input = internalAuthenticate;
		byte[] commandPayload = input.command;
		byte[] responsePayload = input.response;

		// process signature - the only time-critical part of the logic here
		if (!iccPublicKey.verify(commandPayload, responsePayload)) {
			throw new KeyPairInvalidCardMts7Exception();
		}
		LOGGER.info("Verified ICC private key");

		// last, as the card has passed all of the checks
		updateResult(card -> card.setVerifiedPrivateKeyPresent(true));

		LOGGER.info("Processed 'internal authenticate' response");
	}

}
