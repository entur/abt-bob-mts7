package no.entur.abt.bob.mts7.core;

import java.security.NoSuchAlgorithmException;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.core.pki.IccPublicKey;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;

/**
 * 
 * Extracts as much info as possible, also for partial reads. Does not throw exceptions.
 *
 * Note that no info can be trusted unless all checks are completed.
 */

// not thread safe
public class LenientMts7CardFactory {

	private static final Logger LOGGER = LoggerFactory.getLogger(LenientMts7CardFactory.class);

	protected final IccPublicKeyFactory iccPublicKeyFactory = new IccPublicKeyFactory();

	protected final Mts7CardEnricher enricher = new Mts7CardEnricher();
	protected final CBORMapper cborMapper = new CBORMapper();
	protected final ThumbprintFactory thumbprintFactory;

	public LenientMts7CardFactory() throws NoSuchAlgorithmException {
		this.thumbprintFactory = new ThumbprintFactory(null);
	}

	public Mts7Card create(Mts7ApduPayloads card) throws UnableToVerifyKeyPairException {
		Mts7Card result = new Mts7Card();
		try {
			if (card.hasSelectApplicationOutput()) {
				enricher.enrichSelectApplicationResponsePayload(result, card.getSelectApplicationOutput());
			}

			IccPublicKey iccPublicKey = null;

			if (card.hasGetDataOutput()) {

				Map<String, Object> otherValue = cborMapper.readValue(card.getGetDataOutput(), Map.class);
				byte[] p = (byte[]) otherValue.get("p");

				byte[][] cborArray = cborMapper.readValue(p, byte[][].class);

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

					try {
						iccPublicKey = iccPublicKeyFactory.create(m);
					} catch (UnableToConstructIccKeyException e) {
						LOGGER.info("Unable to create ICC public key", e);
					}

					try {
						result.setThumbprint(thumbprintFactory.create(m));
					} catch (UnableToConstructThumbprintKeyException e) {
						LOGGER.info("Unable to construct thumbprint", e);
					}

					break;
				}
			}

			if (iccPublicKey != null && card.hasInternalAuthenticateOutput()
					&& iccPublicKey.verify(card.getInternalAuthenticateInput(), card.getInternalAuthenticateOutput())) {
				result.setVerifiedPrivateKeyPresent(true);
			} else {
				LOGGER.info("Unable to verify ICC private key");
				result.setVerifiedPrivateKeyPresent(false);
			}
		} catch (Exception e) {
			LOGGER.info("Problem processing files", e);
		}

		return result;
	}

}
