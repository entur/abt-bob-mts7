package no.entur.abt.bob.mts7.core;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SignatureException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

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
 * Verify key + trust chain.
 * <p>
 * By default, a card whose root key (the public key of its issuer, by <code>iid</code> and <code>kid</code>) is not among the
 * {@linkplain ParticipantPublicKeys} is rejected. With <code>trustUnknownRootKeys</code>, such a card is accepted if it proves that it has the private key
 * (door 3 only, as {@linkplain VerifyKeyPairMts7CardFactory}), and {@linkplain Mts7Card#isVerifiedTrustChain()} is false. A card whose root key is known must
 * still pass both doors.
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
	protected final boolean trustUnknownRootKeys;

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
		this(participantPublicKeys, provider, false);
	}

	/**
	 * Constructor.
	 *
	 * @param participantPublicKeys issuer keys, shared with other factories and threads
	 * @param provider              security provider (for signatures and digests), or null for the default
	 * @param trustUnknownRootKeys  whether to accept a card whose root key is not among the issuer keys, if it proves that it has the private key
	 * @throws NoSuchAlgorithmException if the digest algorithm is not available
	 */

	public VerifyMts7CardFactory(ParticipantPublicKeys participantPublicKeys, Provider provider, boolean trustUnknownRootKeys) throws NoSuchAlgorithmException {
		this(participantPublicKeys, trustUnknownRootKeys, new IccPublicKeyFactory(provider), new Mts7CardEnricher(), new CBORMapper(),
				new ThumbprintFactory(provider));
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
		this(participantPublicKeys, false, iccPublicKeyFactory, enricher, cborMapper, thumbprintFactory);
	}

	/**
	 * Constructor for sharing the helpers with other factories. All of the helpers must be thread safe.
	 *
	 * @param participantPublicKeys issuer keys, shared with other factories and threads
	 * @param trustUnknownRootKeys  whether to accept a card whose root key is not among the issuer keys, if it proves that it has the private key
	 * @param iccPublicKeyFactory   factory for the public key of the card
	 * @param enricher              card enricher
	 * @param cborMapper            CBOR mapper
	 * @param thumbprintFactory     thumbprint factory
	 */

	public VerifyMts7CardFactory(ParticipantPublicKeys participantPublicKeys, boolean trustUnknownRootKeys, IccPublicKeyFactory iccPublicKeyFactory,
			Mts7CardEnricher enricher, CBORMapper cborMapper, ThumbprintFactory thumbprintFactory) {
		this.participantPublicKeys = participantPublicKeys;
		this.trustUnknownRootKeys = trustUnknownRootKeys;
		this.iccPublicKeyFactory = iccPublicKeyFactory;
		this.enricher = enricher;
		this.cborMapper = cborMapper;
		this.mobileTicketBundleParser = new MobileTicketBundleParser(cborMapper);
		this.thumbprintFactory = thumbprintFactory;
	}

	/**
	 * @return whether a card whose root key is not among the issuer keys is accepted, if it proves that it has the private key
	 */

	public boolean isTrustUnknownRootKeys() {
		return trustUnknownRootKeys;
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
		boolean trustedUnknownRootKey = false;
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
					result.setThumbprint(thumbprintFactory.create(header));
				} catch (UnableToConstructThumbprintKeyException e) {
					LOGGER.info("Unable to construct thumbprint", e);
				}
			}

			try {
				if (iccPublicKeyBuilder.canBuild()) {
					iccPublicKey = iccPublicKeyBuilder.build();

					result.setVerifiedTrustChain(true);
				} else if (trustedUnknownRootKey) {
					// The issuer key is unknown, so the issuer signature of the card certificate (door 2) cannot be checked. Take the public key of
					// the card from the certificate as it is, and only check that the card has the private key for it (door 3), as
					// VerifyKeyPairMts7CardFactory does. This does not say who issued the card, so the trust chain stays not verified.
					iccPublicKey = iccPublicKeyFactory.create(header);
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

		if (!result.isVerifiedTrustChain() && !trustedUnknownRootKey) {
			throw new UnableToVerifyTrustChainException(result);
		}

		return result;
	}

}
