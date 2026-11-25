package no.entur.abt.bob.mts7.reader.processor;

import java.security.SignatureException;
import java.util.concurrent.Executor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.core.Mts7CardEnricher;
import no.entur.abt.bob.mts7.core.UnableToConstructIccKeyException;
import no.entur.abt.bob.mts7.core.UnableToConstructThumbprintKeyException;
import no.entur.abt.bob.mts7.core.UnableToVerifyKeyPairException;
import no.entur.abt.bob.mts7.core.UnableToVerifyTrustChainException;
import no.entur.abt.bob.mts7.core.pki.IccPublicKey;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyBuilder;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.IssuerPublicKey;
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

	// set by the processing thread, read by the thread which waits for the result
	private volatile boolean trustedUnknownRootKey;

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

	public Mts7Card waitForVerify(long timeout) throws InterruptedException, UnableToVerifyKeyPairException, UnableToVerifyTrustChainException {
		Mts7Card card = awaitResult(timeout);

		if (!card.isVerifiedPrivateKeyPresent()) {
			throw new UnableToVerifyKeyPairException(card);
		}

		if (!card.isVerifiedTrustChain() && !trustedUnknownRootKey) {
			throw new UnableToVerifyTrustChainException(card);
		}

		return card;
	}

	@Override
	protected void process() throws Exception {
		IccPublicKeyBuilder iccPublicKeyBuilder = new IccPublicKeyBuilder(iccSignatureFactory);

		if (!awaitInput(() -> selectApplicationResponsePayload != null)) {
			return;
		}

		byte[] selectApplicationResponse = selectApplicationResponsePayload;
		updateResult(card -> enricher.enrichSelectApplicationResponsePayload(card, selectApplicationResponse));

		LOGGER.info("Processed 'select application' response");

		if (!awaitInput(() -> getDataResponsePayload != null)) {
			return;
		}

		MobileTicketBundle mobileTicketBundle = mobileTicketBundleParser.parse(getDataResponsePayload);

		for (byte[] value : mobileTicketBundle.getSignedElements()) {
			iccPublicKeyBuilder.withSignedData(value, 0, value.length);
		}

		iccPublicKeyBuilder.withSignature(mobileTicketBundle.getSignature());

		IccPublicKey iccPublicKey = null;

		IssuerSignatureProtectedHeader header = mobileTicketBundle.getIssuerSignatureProtectedHeader();
		if (header != null) {
			// note here what kind of algorithm we are using
			// EC and RSA do not encode the input to the internal authenticate function
			// in the same way.

			setIccKeyAlgorithm(header.getAlg());

			long iid = Long.parseLong(header.getIid());

			IssuerPublicKey issuerPublicKey = participantPublicKeys.getIssuerPublicKey(iid, header.getKid());

			if (issuerPublicKey == null) {
				LOGGER.info("Unable to find issuer public key");
				// a key which is known, but cannot be used, is not an unknown key
				trustedUnknownRootKey = trustUnknownRootKeys && !participantPublicKeys.hasIssuerPublicKey(iid, header.getKid());
			} else {
				iccPublicKeyBuilder.withIssuerPublicKey(issuerPublicKey);
			}

			iccPublicKeyBuilder.withIssuerSignatureProtectedHeader(header);

			try {
				byte[] thumbprint = thumbprintFactory.create(header);
				updateResult(card -> card.setThumbprint(thumbprint));
			} catch (UnableToConstructThumbprintKeyException e) {
				LOGGER.info("Unable to construct thumbprint", e);
			}
		}

		try {
			if (iccPublicKeyBuilder.canBuild()) {
				iccPublicKey = iccPublicKeyBuilder.build();

				LOGGER.info("Verified ICC trust chain");

				updateResult(card -> card.setVerifiedTrustChain(true));
			} else if (trustedUnknownRootKey) {
				// The issuer key is unknown, so the issuer signature of the card certificate cannot be checked. Take the public key of the card from the
				// certificate as it is, and only check that the card has the private key for it, as VerifyKeyPairMts7Processor does. This does not say
				// who issued the card, so the trust chain stays not verified.
				iccPublicKey = iccSignatureFactory.create(header);
			} else {
				LOGGER.info("Unable to verify ICC trust chain");
			}
		} catch (SignatureException e) {
			LOGGER.info("Issuer signature is not valid", e);
		} catch (UnableToConstructIccKeyException e) {
			LOGGER.info("Unable to create ICC public key", e);
		}

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
		boolean verified = iccPublicKey != null && iccPublicKey.verify(commandPayload, responsePayload);
		if (verified) {
			LOGGER.info("Verified ICC private key");
		} else {
			LOGGER.info("Unable to verify ICC private key");
		}
		updateResult(card -> card.setVerifiedPrivateKeyPresent(verified));

		LOGGER.info("Processed 'internal authenticate' response");
	}

}
