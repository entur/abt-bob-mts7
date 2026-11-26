package no.entur.abt.bob.mts7.core;

import java.io.IOException;
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

	/**
	 * Verify the trust chain of the card, and that the card has the private key for the public key in its certificate.
	 *
	 * @param card the payloads read from the card
	 * @return the verified card
	 * @throws InvalidTrustChainMts7Exception      if the certificate of the card was not signed by a known issuer (door 2): the issuer key is unknown (unless
	 *                                             <code>trustUnknownRootKeys</code>) or not supported, or the issuer signature is not valid (a problem on the
	 *                                             card side)
	 * @throws InvalidKeyPairMts7Exception         if the card did not prove that it has the private key (door 3; a problem on the card side)
	 * @throws InvalidCardMts7Exception            if a response from the card is missing or malformed (a problem on the card side). This is also the superclass
	 *                                             of the above, so catch it for any problem on the card side.
	 * @throws UnableToConstructIssuerKeyException if the issuer key of the card is known, but could not be created (a problem on our side)
	 * @throws NoSuchAlgorithmException            if the signature algorithm of the card is not available from the security provider (a problem on our side)
	 */

	public Mts7Card create(Mts7ApduPayloads card) throws InvalidCardMts7Exception, UnableToConstructIssuerKeyException, NoSuchAlgorithmException {
		Mts7Card result = new Mts7Card();

		if (!card.hasSelectApplicationOutput() || !card.hasGetDataOutput() || !card.hasInternalAuthenticateOutput()) {
			throw new InvalidCardMts7Exception("Missing response from the card", result);
		}

		enricher.enrichSelectApplicationResponsePayload(result, card.getSelectApplicationOutput());

		MobileTicketBundle mobileTicketBundle;
		try {
			mobileTicketBundle = mobileTicketBundleParser.parse(card.getGetDataOutput());
		} catch (IOException e) {
			throw new InvalidCardMts7Exception("Unable to parse the Mobile Ticket Bundle", result, e);
		}

		IssuerSignatureProtectedHeader header = mobileTicketBundle.getIssuerSignatureProtectedHeader();
		if (header == null) {
			throw new InvalidCardMts7Exception("Missing Issuer Signature Protected Header", result);
		}

		try {
			result.setThumbprint(thumbprintFactory.create(header));
		} catch (UnableToConstructThumbprintKeyException e) {
			LOGGER.info("Unable to construct thumbprint", e);
		}

		long iid;
		try {
			iid = Long.parseLong(header.getIid());
		} catch (NumberFormatException e) {
			throw new InvalidCardMts7Exception("Invalid issuer id " + header.getIid(), result, e);
		}

		IccPublicKey iccPublicKey;

		IssuerPublicKey issuerPublicKey = participantPublicKeys.getIssuerPublicKey(iid, header.getKid());
		if (issuerPublicKey != null) {
			IccPublicKeyBuilder iccPublicKeyBuilder = new IccPublicKeyBuilder(iccPublicKeyFactory);
			for (byte[] value : mobileTicketBundle.getSignedElements()) {
				iccPublicKeyBuilder.withSignedData(value, 0, value.length);
			}
			iccPublicKeyBuilder.withSignature(mobileTicketBundle.getSignature());
			iccPublicKeyBuilder.withIssuerSignatureProtectedHeader(header);
			iccPublicKeyBuilder.withIssuerPublicKey(issuerPublicKey);

			try {
				iccPublicKey = iccPublicKeyBuilder.build();
			} catch (SignatureException e) {
				throw new InvalidTrustChainMts7Exception("Issuer signature is not valid", result);
			} catch (UnableToConstructIccKeyException e) {
				throw new InvalidCardMts7Exception("Unable to create ICC public key", result, e);
			}
			result.setVerifiedTrustChain(true);
		} else if (participantPublicKeys.hasIssuerPublicKey(iid, header.getKid())) {
			// a key which is known, but cannot be used, is not an unknown key
			throw new InvalidTrustChainMts7Exception("Issuer public key " + header.getKid() + " of participant " + iid + " is not supported", result);
		} else if (trustUnknownRootKeys) {
			// The issuer key is unknown, so the issuer signature of the card certificate (door 2) cannot be checked. Take the public key of
			// the card from the certificate as it is, and only check that the card has the private key for it (door 3), as
			// VerifyKeyPairMts7CardFactory does. This does not say who issued the card, so the trust chain stays not verified.
			try {
				iccPublicKey = iccPublicKeyFactory.create(header);
			} catch (UnableToConstructIccKeyException e) {
				throw new InvalidCardMts7Exception("Unable to create ICC public key", result, e);
			}
		} else {
			throw new InvalidTrustChainMts7Exception("Unknown issuer public key " + header.getKid() + " of participant " + iid, result);
		}

		if (!iccPublicKey.verify(card.getInternalAuthenticateInput(), card.getInternalAuthenticateOutput())) {
			throw new InvalidKeyPairMts7Exception(result);
		}
		result.setVerifiedPrivateKeyPresent(true);

		return result;
	}

}
