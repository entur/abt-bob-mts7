package no.entur.abt.bob.mts7.core;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SignatureException;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.core.pki.IccPublicKey;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyBuilder;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.IssuerPublicKey;
import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;

/**
 * 
 * Verify key + trust chain.
 * <p>
 * Instances are thread safe, so a single instance should be shared by all threads (this requires that the {@linkplain ParticipantPublicKeys} is shared too).
 * 
 */

public class VerifyMts7CardFactory {

	private static final Logger LOGGER = LoggerFactory.getLogger(VerifyMts7CardFactory.class);

	protected final IccPublicKeyFactory iccPublicKeyFactory;

	protected final Mts7CardEnricher enricher;
	protected final CBORMapper cborMapper;
	protected final ThumbprintFactory thumbprintFactory;
	protected final ParticipantPublicKeys participantPublicKeys;

	public VerifyMts7CardFactory(ParticipantPublicKeys participantPublicKeys) throws NoSuchAlgorithmException {
		this(participantPublicKeys, null);
	}

	/**
	 * Constructor.
	 *
	 * @param participantPublicKeys issuer keys, shared with other factories and threads
	 * @param provider              security provider (for signatures and digests), or null for the default
	 * @throws NoSuchAlgorithmException if the digest algorithm is not available
	 */

	public VerifyMts7CardFactory(ParticipantPublicKeys participantPublicKeys, Provider provider) throws NoSuchAlgorithmException {
		this(participantPublicKeys, new IccPublicKeyFactory(provider), new Mts7CardEnricher(), new CBORMapper(), new ThumbprintFactory(provider));
	}

	/**
	 * Constructor for sharing the helpers with other factories. All of the helpers must be thread safe.
	 *
	 * @param participantPublicKeys issuer keys, shared with other factories and threads
	 * @param iccPublicKeyFactory   factory for the public key of the card
	 * @param enricher              card enricher
	 * @param cborMapper            CBOR mapper
	 * @param thumbprintFactory     thumbprint factory
	 */

	public VerifyMts7CardFactory(ParticipantPublicKeys participantPublicKeys, IccPublicKeyFactory iccPublicKeyFactory, Mts7CardEnricher enricher,
			CBORMapper cborMapper, ThumbprintFactory thumbprintFactory) {
		this.participantPublicKeys = participantPublicKeys;
		this.iccPublicKeyFactory = iccPublicKeyFactory;
		this.enricher = enricher;
		this.cborMapper = cborMapper;
		this.thumbprintFactory = thumbprintFactory;
	}

	public Mts7Card create(Mts7ApduPayloads card) throws UnableToVerifyKeyPairException, UnableToVerifyTrustChainException {
		Mts7Card result = new Mts7Card();
		try {
			IccPublicKeyBuilder iccPublicKeyBuilder = new IccPublicKeyBuilder(iccPublicKeyFactory);

			enricher.enrichSelectApplicationResponsePayload(result, card.getSelectApplicationOutput());

			Map<String, Object> otherValue = cborMapper.readValue(card.getGetDataOutput(), Map.class);
			byte[] p = (byte[]) otherValue.get("p");

			byte[][] cborArray = cborMapper.readValue(p, byte[][].class);

			for (int i = 0; i < cborArray.length - 1; i++) {
				byte[] value = cborArray[i];
				iccPublicKeyBuilder.withSignedData(value, 0, value.length);
			}

			byte[] signature = cborArray[cborArray.length - 1];
			iccPublicKeyBuilder.withSignature(signature);

			IccPublicKey iccPublicKey = null;

			String iccKeyAlgorithm = null;

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

				String kid = (String) kidObject;
				Long iid = Long.parseLong(iidObject.toString());

				// note here what kind of algorithm we are using
				// EC and RSA do not encode the input to the internal authenticate function
				// in the same way.

				iccKeyAlgorithm = (String) m.get("alg");

				IssuerPublicKey issuerPublicKey = participantPublicKeys.getIssuerPublicKey(iid, kid);

				if (issuerPublicKey == null) {
					LOGGER.info("Unable to find issuer public key");
				} else {
					iccPublicKeyBuilder.withIssuerPublicKey(issuerPublicKey);
				}

				iccPublicKeyBuilder.withIssuerSignatureProtectedHeader(m);

				try {
					result.setThumbprint(thumbprintFactory.create(m));
				} catch (UnableToConstructThumbprintKeyException e) {
					// a card can be anything, so do not fill the log
					LOGGER.info("Unable to construct thumbprint: {}", e.toString());
					LOGGER.debug("Unable to construct thumbprint", e);
				}

				break;
			}

			try {
				if (iccPublicKeyBuilder.canBuild()) {
					iccPublicKey = iccPublicKeyBuilder.build();

					result.setVerifiedTrustChain(true);
				} else {
					LOGGER.info("Unable to verify ICC trust chain");
				}
			} catch (SignatureException e) {
				// a card can be anything, so do not fill the log
				LOGGER.info("Issuer signature is not valid: {}", e.toString());
				LOGGER.debug("Issuer signature is not valid", e);
			} catch (UnableToConstructIccKeyException e) {
				// a card can be anything, so do not fill the log
				LOGGER.info("Unable to create ICC public key: {}", e.toString());
				LOGGER.debug("Unable to create ICC public key", e);
			}

			if (iccPublicKey != null && iccPublicKey.verify(card.getInternalAuthenticateInput(), card.getInternalAuthenticateOutput())) {
				result.setVerifiedPrivateKeyPresent(true);
			} else {
				LOGGER.info("Unable to verify ICC private key");
				result.setVerifiedPrivateKeyPresent(false);
			}
		} catch (Exception e) {
			// a card can be anything, so do not fill the log
			LOGGER.info("Problem processing files: {}", e.toString());
			LOGGER.debug("Problem processing files", e);
		}

		if (!result.isVerifiedPrivateKeyPresent()) {
			throw new UnableToVerifyKeyPairException(result);
		}

		if (!result.isVerifiedTrustChain()) {
			throw new UnableToVerifyTrustChainException(result);
		}

		return result;
	}

	/**
	 * Do the work which otherwise is done for the first card, so call this when the application starts (for example on a background thread). Never throws.
	 */

	public void warmUp() {
		Mts7Warmup.warmUp(cborMapper, enricher, iccPublicKeyFactory);
	}

}
