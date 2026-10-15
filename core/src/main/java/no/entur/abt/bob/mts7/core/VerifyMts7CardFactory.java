package no.entur.abt.bob.mts7.core;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SignatureException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.core.mtb.IssuerSignatureProtectedHeader;
import no.entur.abt.bob.mts7.core.mtb.MobileTicketBundle;
import no.entur.abt.bob.mts7.core.mtb.MobileTicketBundleParser;
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
	protected final MobileTicketBundleParser mobileTicketBundleParser;
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
		this.mobileTicketBundleParser = new MobileTicketBundleParser(cborMapper);
		this.thumbprintFactory = thumbprintFactory;
	}

	/**
	 * @return the factory for the public key of the card, which can be shared with other factories
	 */

	public IccPublicKeyFactory getIccPublicKeyFactory() {
		return iccPublicKeyFactory;
	}

	/**
	 * @return the card enricher, which can be shared with other factories
	 */

	public Mts7CardEnricher getEnricher() {
		return enricher;
	}

	/**
	 * @return the CBOR mapper, which can be shared with other factories
	 */

	public CBORMapper getCborMapper() {
		return cborMapper;
	}

	/**
	 * @return the thumbprint factory, which can be shared with other factories
	 */

	public ThumbprintFactory getThumbprintFactory() {
		return thumbprintFactory;
	}

	public Mts7Card create(Mts7ApduPayloads card) throws UnableToVerifyKeyPairException, UnableToVerifyTrustChainException {
		Mts7Card result = new Mts7Card();
		try {
			IccPublicKeyBuilder iccPublicKeyBuilder = new IccPublicKeyBuilder(iccPublicKeyFactory);

			enricher.enrichSelectApplicationResponsePayload(result, card.getSelectApplicationOutput());

			MobileTicketBundle mobileTicketBundle = mobileTicketBundleParser.parse(card.getGetDataOutput());

			for (byte[] value : mobileTicketBundle.getSignedElements()) {
				iccPublicKeyBuilder.withSignedData(value, 0, value.length);
			}

			iccPublicKeyBuilder.withSignature(mobileTicketBundle.getSignature());

			IccPublicKey iccPublicKey = null;

			IssuerSignatureProtectedHeader header = mobileTicketBundle.getIssuerSignatureProtectedHeader();
			if (header != null) {
				IssuerPublicKey issuerPublicKey = participantPublicKeys.getIssuerPublicKey(Long.parseLong(header.getIid()), header.getKid());

				if (issuerPublicKey == null) {
					LOGGER.info("Unable to find issuer public key");
				} else {
					iccPublicKeyBuilder.withIssuerPublicKey(issuerPublicKey);
				}

				iccPublicKeyBuilder.withIssuerSignatureProtectedHeader(header);

				try {
					result.setThumbprint(thumbprintFactory.create(header));
				} catch (UnableToConstructThumbprintKeyException e) {
					LOGGER.info("Unable to construct thumbprint", e);
				}
			}

			try {
				if (iccPublicKeyBuilder.canBuild()) {
					iccPublicKey = iccPublicKeyBuilder.build();

					result.setVerifiedTrustChain(true);
				} else {
					LOGGER.info("Unable to verify ICC trust chain");
				}
			} catch (SignatureException e) {
				LOGGER.info("Issuer signature is not valid", e);
			} catch (UnableToConstructIccKeyException e) {
				LOGGER.info("Unable to create ICC public key", e);
			}

			if (iccPublicKey != null && iccPublicKey.verify(card.getInternalAuthenticateInput(), card.getInternalAuthenticateOutput())) {
				result.setVerifiedPrivateKeyPresent(true);
			} else {
				LOGGER.info("Unable to verify ICC private key");
				result.setVerifiedPrivateKeyPresent(false);
			}
		} catch (Exception e) {
			LOGGER.info("Problem processing files", e);
		}

		if (!result.isVerifiedPrivateKeyPresent()) {
			throw new UnableToVerifyKeyPairException(result);
		}

		if (!result.isVerifiedTrustChain()) {
			throw new UnableToVerifyTrustChainException(result);
		}

		return result;
	}

}
