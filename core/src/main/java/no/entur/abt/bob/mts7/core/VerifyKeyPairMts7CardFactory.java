package no.entur.abt.bob.mts7.core;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.core.pki.IccPublicKey;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
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

	private static final Logger LOGGER = LoggerFactory.getLogger(VerifyKeyPairMts7CardFactory.class);

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
	 * @throws InvalidKeyPairMts7Exception if the card did not prove that it has the private key (a problem on the card side)
	 * @throws InvalidCardMts7Exception    if a response from the card is missing or malformed (a problem on the card side). This is also the superclass of
	 *                                     {@linkplain InvalidKeyPairMts7Exception}, so catch it for any problem on the card side.
	 * @throws NoSuchAlgorithmException    if the signature algorithm of the card is not available from the security provider (a problem on our side)
	 */

	public Mts7Card create(Mts7ApduPayloads card) throws InvalidCardMts7Exception, NoSuchAlgorithmException {
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

		IccPublicKey iccPublicKey;
		try {
			iccPublicKey = iccPublicKeyFactory.create(header);
		} catch (UnableToConstructIccKeyException e) {
			throw new InvalidCardMts7Exception("Unable to create ICC public key", result, e);
		}

		if (!iccPublicKey.verify(card.getInternalAuthenticateInput(), card.getInternalAuthenticateOutput())) {
			throw new InvalidKeyPairMts7Exception(result);
		}
		result.setVerifiedPrivateKeyPresent(true);

		return result;
	}

}
