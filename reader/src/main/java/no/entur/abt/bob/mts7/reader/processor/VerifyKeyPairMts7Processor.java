package no.entur.abt.bob.mts7.reader.processor;

import java.io.IOException;
import java.util.concurrent.Executor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.core.IccKeyInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.KeyPairInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.Mts7CardEnricher;
import no.entur.abt.bob.mts7.core.UnableToConstructIccKeyException;
import no.entur.abt.bob.mts7.core.pki.IccPublicKey;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.Mts1Algorithms;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;
import no.entur.abt.bob.mts7.mtb.IssuerSignatureProtectedHeader;
import no.entur.abt.bob.mts7.mtb.MobileTicketBundle;
import no.entur.abt.bob.mts7.mtb.MobileTicketBundleParser;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * 
 * Processor for MTS7 card integrity check. This only verifies that the card has the private key, not the key chain.
 * <p>
 * A processor is for one card only.
 * 
 */

public class VerifyKeyPairMts7Processor extends AbstractMts7Processor {

	private static final Logger LOGGER = LoggerFactory.getLogger(VerifyKeyPairMts7Processor.class);

	protected final IccPublicKeyFactory iccSignatureFactory;
	protected final CBORMapper cborMapper;
	protected final MobileTicketBundleParser mobileTicketBundleParser;
	protected final Mts7CardEnricher enricher;

	protected final ThumbprintFactory thumbprintFactory;

	public VerifyKeyPairMts7Processor(IccPublicKeyFactory factory, Mts7CardEnricher enricher, CBORMapper cborMapper, ThumbprintFactory thumbprintFactory,
			Executor executor) {
		super(executor);

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
			throw new InvalidCardMts7Exception("Unable to parse the Mobile Ticket Bundle", result, e);
		}

		IssuerSignatureProtectedHeader header = mobileTicketBundle.getIssuerSignatureProtectedHeader();
		if (header == null) {
			throw new InvalidCardMts7Exception("Missing Issuer Signature Protected Header", result);
		}

		// note here what kind of algorithm the card uses: EC and RSA do not encode the input to the internal authenticate function in the same way. It
		// follows from the type of the public key of the card, not from alg in the header, which is the algorithm of the issuer signature.

		setIccKeyAlgorithm(Mts1Algorithms.getTokenAlgorithm(header.getTpk()));

		IccPublicKey iccPublicKey;
		try {
			iccPublicKey = iccSignatureFactory.create(header);
		} catch (UnableToConstructIccKeyException e) {
			throw new IccKeyInvalidCardMts7Exception(result, e);
		}

		// from the same token public key as the public key of the card, which could be created, so a problem here is on our side
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

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(ByteArrayHexStringConverter.toHexString(responsePayload));
		}

		// process signature - the only time-critical part of the logic here
		if (!iccPublicKey.verify(commandPayload, responsePayload)) {
			throw new KeyPairInvalidCardMts7Exception(result);
		}
		LOGGER.info("Verified ICC private key");

		// last, as the card has passed all of the checks
		updateResult(card -> card.setVerifiedPrivateKeyPresent(true));

		LOGGER.info("Processed 'internal authenticate' response");
	}

}
