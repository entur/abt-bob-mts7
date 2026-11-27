package no.entur.abt.bob.mts7.core;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Objects;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.api.InfrastructureMts7Exception;
import no.entur.abt.bob.mts7.api.InsufficientCardCommandsException;
import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.api.ReaderMts7Exception;
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

	protected final IccPublicKeyFactory iccPublicKeyFactory;

	protected final Mts7CardEnricher enricher;
	protected final CBORMapper cborMapper;
	protected final MobileTicketBundleParser mobileTicketBundleParser;
	protected final ThumbprintFactory thumbprintFactory;
	protected final ParticipantPublicKeys participantPublicKeys;
	protected final boolean trustUnknownRootKeys;
	protected final UnknownIssuerKeyPolicy unknownIssuerKeyPolicy;

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
	 * @param participantPublicKeys  issuer keys, shared with other factories and threads
	 * @param provider               security provider (for signatures and digests), or null for the default
	 * @param unknownIssuerKeyPolicy who is to blame for a card whose issuer key is not among the issuer keys
	 * @throws NoSuchAlgorithmException if the digest algorithm is not available
	 */

	public VerifyMts7CardFactory(ParticipantPublicKeys participantPublicKeys, Provider provider, UnknownIssuerKeyPolicy unknownIssuerKeyPolicy)
			throws NoSuchAlgorithmException {
		this(participantPublicKeys, false, unknownIssuerKeyPolicy, new IccPublicKeyFactory(provider), new Mts7CardEnricher(), new CBORMapper(),
				new ThumbprintFactory(provider));
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
		this(participantPublicKeys, trustUnknownRootKeys, UnknownIssuerKeyPolicy.blameCard(), iccPublicKeyFactory, enricher, cborMapper, thumbprintFactory);
	}

	/**
	 * Constructor for sharing the helpers with other factories. All of the helpers must be thread safe.
	 *
	 * @param participantPublicKeys  issuer keys, shared with other factories and threads
	 * @param trustUnknownRootKeys   whether to accept a card whose root key is not among the issuer keys, if it proves that it has the private key
	 * @param unknownIssuerKeyPolicy who is to blame for a card whose issuer key is not among the issuer keys (unless trustUnknownRootKeys)
	 * @param iccPublicKeyFactory    factory for the public key of the card
	 * @param enricher               card enricher
	 * @param cborMapper             CBOR mapper
	 * @param thumbprintFactory      thumbprint factory
	 */

	public VerifyMts7CardFactory(ParticipantPublicKeys participantPublicKeys, boolean trustUnknownRootKeys, UnknownIssuerKeyPolicy unknownIssuerKeyPolicy,
			IccPublicKeyFactory iccPublicKeyFactory, Mts7CardEnricher enricher, CBORMapper cborMapper, ThumbprintFactory thumbprintFactory) {
		this.participantPublicKeys = participantPublicKeys;
		this.trustUnknownRootKeys = trustUnknownRootKeys;
		this.unknownIssuerKeyPolicy = Objects.requireNonNull(unknownIssuerKeyPolicy, "unknownIssuerKeyPolicy");
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
	 * @return who is to blame for a card whose issuer key is not among the issuer keys
	 */

	public UnknownIssuerKeyPolicy getUnknownIssuerKeyPolicy() {
		return unknownIssuerKeyPolicy;
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
	 * Verify the trust chain of the card, and that the card has the private key for the public key in its certificate. The card is checked as far as it can be
	 * before a problem with the reader is reported, so that a card which is not valid is to blame for that, whatever else it did.
	 *
	 * @param card the payloads read from the card
	 * @return the verified card
	 * @throws UnknownIssuerKeyInvalidCardMts7Exception   if the issuer key of the certificate of the card is unknown (door 2, unless
	 *                                                    <code>trustUnknownRootKeys</code>; a problem on the card side, or the participant metadata is out of
	 *                                                    date)
	 * @throws TrustChainInvalidCardMts7Exception         if the certificate of the card was not signed by a known issuer (door 2): the issuer signature is not
	 *                                                    valid, its algorithm does not match the issuer key, or (as the subclass above) the issuer key is
	 *                                                    unknown (a problem on the card side)
	 * @throws KeyPairInvalidCardMts7Exception            if the card did not prove that it has the private key (door 3; a problem on the card side)
	 * @throws NonCompliantIccKeyInvalidCardMts7Exception if the public key of the card in its certificate is missing or not valid (a problem on the card side)
	 * @throws InvalidCardMts7Exception                   if a response from the card is missing or malformed, including an issuer signature algorithm which is
	 *                                                    missing or not as in MTS1 (a problem on the card side). This is also the superclass of the above, so
	 *                                                    catch it for any problem on the card side.
	 * @throws UnableToConstructIssuerKeyException        if the issuer key of the card is known, but could not be created, is not supported, or is not accepted
	 *                                                    by the security provider (a problem on our side)
	 * @throws NoSuchAlgorithmMts7Exception               if a signature algorithm is not available from the security provider (a problem on our side)
	 * @throws UnableToConstructThumbprintKeyException    if the thumbprint of the public key of the card could not be created, although the key could (a
	 *                                                    problem on our side)
	 * @throws ReaderMts7Exception                        if the input is incomplete or malformed, as it was not read as MTS7 specifies (a problem with the
	 *                                                    reader)
	 * @throws InfrastructureMts7Exception                if the card could not be verified because of a problem on our side. This is also the superclass of the
	 *                                                    three above, so catch it for any problem on our side.
	 */

	public Mts7Card create(Mts7ApduPayloads card) throws InvalidCardMts7Exception, ReaderMts7Exception, InfrastructureMts7Exception {
		Mts7Card result = new Mts7Card();

		// The card is checked as far as it can be before a problem with the reader is reported, so that a card which is not valid is to blame for that,
		// whatever else it did: door 2 needs the MTB, door 3 also the signature, and the application-related data is read last.

		// what is missing was not read, which is not the fault of the card
		if (!card.hasGetDataOutput()) {
			throw missing(card);
		}

		MobileTicketBundle mobileTicketBundle;
		try {
			mobileTicketBundle = mobileTicketBundleParser.parse(card.getGetDataOutput());
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

		long iid;
		try {
			iid = Long.parseLong(header.getIid());
		} catch (NumberFormatException e) {
			throw new InvalidCardMts7Exception("Invalid issuer id " + header.getIid(), e);
		}

		IccPublicKey iccPublicKey;

		IssuerPublicKey issuerPublicKey = participantPublicKeys.getIssuerPublicKey(iid, header.getKid());
		if (issuerPublicKey != null) {
			IccPublicKeyBuilder iccPublicKeyBuilder = new IccPublicKeyBuilder(iccPublicKeyFactory);
			iccPublicKeyBuilder.withEncodedSignedData(mobileTicketBundle.getSignedData());
			iccPublicKeyBuilder.withSignature(mobileTicketBundle.getSignature());
			iccPublicKeyBuilder.withIssuerSignatureProtectedHeader(header);
			iccPublicKeyBuilder.withIssuerPublicKey(issuerPublicKey);

			iccPublicKey = iccPublicKeyBuilder.build();
			result.setVerifiedTrustChain(true);
		} else if (participantPublicKeys.hasIssuerPublicKey(iid, header.getKid())) {
			// a key which is known, but which we cannot use, is not an unknown key, and not the fault of the card
			throw new UnableToConstructIssuerKeyException("Issuer public key " + header.getKid() + " of participant " + iid + " is not supported");
		} else if (trustUnknownRootKeys) {
			// The issuer key is unknown, so the issuer signature of the card certificate (door 2) cannot be checked. Take the public key of
			// the card from the certificate as it is, and only check that the card has the private key for it (door 3), as
			// VerifyKeyPairMts7CardFactory does. This does not say who issued the card, so the trust chain stays not verified.
			iccPublicKey = iccPublicKeyFactory.create(header);
		} else if (unknownIssuerKeyPolicy.isCardToBlame(iid, header.getKid(), participantPublicKeys)) {
			throw new UnknownIssuerKeyInvalidCardMts7Exception(iid, header.getKid());
		} else {
			// our keys may be out of date
			throw new OutdatedIssuerKeysException(iid, header.getKid());
		}

		// from the same token public key as the public key of the card, which could be created, so a problem here is expected to be on our side
		result.setThumbprint(thumbprintFactory.create(header));

		verifyPrivateKey(card, iccPublicKey);

		enrich(enricher, result, card);

		// last, as the card has passed all of the checks
		result.setVerifiedPrivateKeyPresent(true);

		return result;
	}

	/**
	 * @return the problem with the reader because of which a response is missing, or {@linkplain MissingCardCommandsException} if it is not known
	 */

	static ReaderMts7Exception missing(Mts7ApduPayloads card) {
		if (card.hasReaderProblem()) {
			return card.getReaderProblem();
		}
		return new MissingCardCommandsException("Missing response from the card");
	}

	/**
	 * Door 3: check that the card has the private key, from its signature of the challenge.
	 */

	static void verifyPrivateKey(Mts7ApduPayloads card, IccPublicKey iccPublicKey)
			throws InvalidCardMts7Exception, ReaderMts7Exception, InfrastructureMts7Exception {
		if (!card.hasInternalAuthenticateOutput()) {
			throw missing(card);
		}
		byte[] challenge = card.getInternalAuthenticateInput();
		if (challenge == null || challenge.length != Mts7ApduPayloadsFactory.CHALLENGE_LENGTH) {
			// a SHA-256 hash (MTS7 section 4.1.4)
			throw new MalformedCardCommandException("Challenge for internal authenticate of " + (challenge == null ? 0 : challenge.length) + " bytes, not "
					+ Mts7ApduPayloadsFactory.CHALLENGE_LENGTH);
		}
		iccPublicKey.verify(challenge, card.getInternalAuthenticateOutput());
	}

	/**
	 * Enrich the card with its application-related data, from the select application response or from GET DATA of it.
	 */

	static void enrich(Mts7CardEnricher enricher, Mts7Card result, Mts7ApduPayloads card) throws InvalidCardMts7Exception, ReaderMts7Exception {
		try {
			enricher.enrich(result, card.getSelectApplicationOutput(), card.getApplicationRelatedDataOutput());
		} catch (InsufficientCardCommandsException e) {
			// why it is missing, if known
			throw card.hasReaderProblem() ? card.getReaderProblem() : e;
		}
	}

}
