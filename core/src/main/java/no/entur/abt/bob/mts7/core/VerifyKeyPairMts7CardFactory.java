package no.entur.abt.bob.mts7.core;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.core.pki.IccPublicKey;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.Mts1Algorithms;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;
import no.entur.abt.bob.mts7.mtb.IssuerSignatureProtectedHeader;
import no.entur.abt.bob.mts7.mtb.MobileTicketBundle;
import no.entur.abt.bob.mts7.mtb.MobileTicketBundleParser;

/**
 * 
 * Verify key (not trust chain).
 * <p>
 * Instances are thread safe, so a single instance should be shared by all threads.
 * 
 */

public class VerifyKeyPairMts7CardFactory {

	protected final IccPublicKeyFactory iccPublicKeyFactory;

	protected final Mts7CardEnricher enricher;
	protected final CBORMapper cborMapper;
	protected final MobileTicketBundleParser mobileTicketBundleParser;
	protected final ThumbprintFactory thumbprintFactory;

	public VerifyKeyPairMts7CardFactory() throws NoSuchAlgorithmException {
		this((Provider) null);
	}

	/**
	 * Constructor.
	 *
	 * @param provider security provider (for signatures and digests), or null for the default
	 * @throws NoSuchAlgorithmException if the digest algorithm is not available
	 */

	public VerifyKeyPairMts7CardFactory(Provider provider) throws NoSuchAlgorithmException {
		this(new IccPublicKeyFactory(provider), new Mts7CardEnricher(), new CBORMapper(), new ThumbprintFactory(provider));
	}

	/**
	 * Constructor for sharing the helpers with other factories. All of the helpers must be thread safe.
	 *
	 * @param iccPublicKeyFactory factory for the public key of the card
	 * @param enricher            card enricher
	 * @param cborMapper          CBOR mapper
	 * @param thumbprintFactory   thumbprint factory
	 */

	public VerifyKeyPairMts7CardFactory(IccPublicKeyFactory iccPublicKeyFactory, Mts7CardEnricher enricher, CBORMapper cborMapper,
			ThumbprintFactory thumbprintFactory) {
		this.iccPublicKeyFactory = iccPublicKeyFactory;
		this.enricher = enricher;
		this.cborMapper = cborMapper;
		this.mobileTicketBundleParser = new MobileTicketBundleParser(cborMapper);
		this.thumbprintFactory = thumbprintFactory;
	}

	/**
	 * Verify that the card has the private key for the public key in its certificate.
	 *
	 * @param card the payloads read from the card
	 * @return the verified card
	 * @throws KeyPairInvalidCardMts7Exception         if the card did not prove that it has the private key (a problem on the card side)
	 * @throws IccKeyInvalidCardMts7Exception          if the public key of the card in its certificate is missing or not valid (a problem on the card side)
	 * @throws InvalidCardMts7Exception                if a response from the card is missing or malformed, including an issuer signature algorithm which is
	 *                                                 missing or not as in MTS1 (a problem on the card side). This is also the superclass of the above, so
	 *                                                 catch it for any problem on the card side.
	 * @throws NoSuchAlgorithmMts7Exception            if the signature algorithm of the card is not available from the security provider (a problem on our
	 *                                                 side)
	 * @throws UnableToConstructThumbprintKeyException if the thumbprint of the public key of the card could not be created, although the key could (a problem
	 *                                                 on our side)
	 * @throws InfrastructureMts7Exception             if the card could not be verified because of a problem on our side. This is also the superclass of the
	 *                                                 two above, so catch it for any problem on our side.
	 */

	public Mts7Card create(Mts7ApduPayloads card) throws InvalidCardMts7Exception, InfrastructureMts7Exception {
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

		// MTS1 requires alg, the algorithm of the issuer signature, and has two. Checked before anything else in the header, so that a card which is
		// not as in the specification is to blame, whatever happens on our side with the issuer key.
		if (!Mts1Algorithms.isIssuerSignatureAlgorithm(header.getAlg())) {
			throw new InvalidCardMts7Exception(
					"Issuer signature algorithm " + header.getAlg() + " is not " + Mts1Algorithms.ES256 + " or " + Mts1Algorithms.RS256, result);
		}

		IccPublicKey iccPublicKey;
		try {
			iccPublicKey = iccPublicKeyFactory.create(header);
		} catch (UnableToConstructIccKeyException e) {
			throw new IccKeyInvalidCardMts7Exception(result, e);
		}

		// from the same token public key as the public key of the card, which could be created, so a problem here is on our side
		try {
			result.setThumbprint(thumbprintFactory.create(header));
		} catch (UnableToConstructIccKeyException e) {
			// not after the key could be created, but the card is to blame
			throw new IccKeyInvalidCardMts7Exception(result, e);
		}

		if (!iccPublicKey.verify(card.getInternalAuthenticateInput(), card.getInternalAuthenticateOutput())) {
			throw new KeyPairInvalidCardMts7Exception(result);
		}
		result.setVerifiedPrivateKeyPresent(true);

		return result;
	}

}
