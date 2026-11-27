package no.entur.abt.bob.mts7.core;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.api.ReaderMts7Exception;
import no.entur.abt.bob.mts7.api.VerifierMts7Exception;
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
	 * @throws KeyPairInvalidCardMts7Exception            if the card did not prove that it has the private key (a problem on the card side)
	 * @throws NonCompliantIccKeyInvalidCardMts7Exception if the public key of the card in its certificate is missing or not valid (a problem on the card side)
	 * @throws InvalidCardMts7Exception                   if a response from the card is missing or malformed, including an issuer signature algorithm which is
	 *                                                    missing or not as in MTS1 (a problem on the card side). This is also the superclass of the above, so
	 *                                                    catch it for any problem on the card side.
	 * @throws NoSuchAlgorithmMts7Exception               if the signature algorithm of the card is not available from the security provider (a problem with the
	 *                                                    verifier)
	 * @throws UnableToConstructThumbprintKeyException    if the thumbprint of the public key of the card could not be created, although the key could (a
	 *                                                    problem with the verifier)
	 * @throws ReaderMts7Exception                        if the input is incomplete or malformed, as it was not read as MTS7 specifies (a problem with the
	 *                                                    reader)
	 * @throws VerifierMts7Exception                      if the card could not be verified because of a problem with the verifier. This is also the superclass
	 *                                                    of the two above, so catch it for any problem with the verifier.
	 */

	public Mts7Card create(Mts7ApduPayloads card) throws InvalidCardMts7Exception, ReaderMts7Exception, VerifierMts7Exception {
		Mts7Card result = new Mts7Card();

		// The card is checked as far as it can be before a problem with the reader is reported, so that a card which is not valid is to blame for that,
		// whatever else it did: door 3 needs the MTB and the signature, and the application-related data is read last.

		// what is missing was not read, which is not the fault of the card
		if (!card.hasGetDataOutput()) {
			throw VerifyMts7CardFactory.missing(card);
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
		// not as in the specification is to blame, whatever happens with the issuer key in the verifier.
		if (!Mts1Algorithms.isIssuerSignatureAlgorithm(header.getAlg())) {
			throw new InvalidCardMts7Exception(
					"Issuer signature algorithm " + header.getAlg() + " is not " + Mts1Algorithms.ES256 + " or " + Mts1Algorithms.RS256);
		}

		IccPublicKey iccPublicKey;
		iccPublicKey = iccPublicKeyFactory.create(header);

		// from the same token public key as the public key of the card, which could be created, so a problem here is expected to be with the verifier
		result.setThumbprint(thumbprintFactory.create(header));

		VerifyMts7CardFactory.verifyPrivateKey(card, iccPublicKey);

		VerifyMts7CardFactory.enrich(enricher, result, card);

		// last, as the card has passed all of the checks
		result.setVerifiedPrivateKeyPresent(true);

		return result;
	}

}
