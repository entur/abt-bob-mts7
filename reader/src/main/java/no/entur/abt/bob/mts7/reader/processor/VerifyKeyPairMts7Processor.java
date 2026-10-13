package no.entur.abt.bob.mts7.reader.processor;

import java.util.Map;
import java.util.concurrent.Executor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.core.Mts7CardEnricher;
import no.entur.abt.bob.mts7.core.UnableToConstructIccKeyException;
import no.entur.abt.bob.mts7.core.UnableToConstructThumbprintKeyException;
import no.entur.abt.bob.mts7.core.UnableToVerifyKeyPairException;
import no.entur.abt.bob.mts7.core.pki.IccPublicKey;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;
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
	protected final Mts7CardEnricher enricher;

	protected final ThumbprintFactory thumbprintFactory;

	public VerifyKeyPairMts7Processor(IccPublicKeyFactory factory, Mts7CardEnricher enricher, CBORMapper cborMapper, ThumbprintFactory thumbprintFactory,
			Executor executor) {
		super(executor);

		this.iccSignatureFactory = factory;

		this.cborMapper = cborMapper;
		this.enricher = enricher;
		this.thumbprintFactory = thumbprintFactory;
	}

	public Mts7Card waitForVerify(long timeout) throws InterruptedException, UnableToVerifyKeyPairException {
		Mts7Card card = awaitResult(timeout);

		if (!card.isVerifiedPrivateKeyPresent()) {
			throw new UnableToVerifyKeyPairException(card);
		}

		return card;
	}

	@SuppressWarnings("unchecked")
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

		Map<String, Object> otherValue = cborMapper.readValue(getDataResponsePayload, Map.class);
		byte[] p = (byte[]) otherValue.get("p");

		byte[][] cborArray = cborMapper.readValue(p, byte[][].class);

		IccPublicKey iccPublicKey = null;

		// determine which issuer key to use
		for (int i = 0; i < cborArray.length - 1; i++) {
			byte[] value = cborArray[i];

			Map<String, Object> m = cborMapper.readValue(value, Map.class);

			// To be able to distinguish between the Issuer Signature and the Device Signature (see section 2.5) header, the Issuer Signature Protected
			// Header MUST NOT contain a did parameter.
			if (m.containsKey("did")) {
				continue;
			}

			Object kidObject = m.get("kid");
			if (kidObject == null) {
				continue;
			}

			Object iidObject = m.get("iid");
			if (iidObject == null) {
				continue;
			}

			// note here what kind of algorithm we are using
			// EC and RSA do not encode the input to the internal authenticate function
			// in the same way.

			setIccKeyAlgorithm((String) m.get("alg"));

			try {
				iccPublicKey = iccSignatureFactory.create(m);
			} catch (UnableToConstructIccKeyException e) {
				LOGGER.info("Unable to create ICC public key", e);
			}

			try {
				byte[] thumbprint = thumbprintFactory.create(m);
				updateResult(card -> card.setThumbprint(thumbprint));
			} catch (UnableToConstructThumbprintKeyException e) {
				LOGGER.info("Unable to construct thumbprint", e);
			}

			break;
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

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(ByteArrayHexStringConverter.toHexString(responsePayload));
		}

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
