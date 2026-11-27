package no.entur.abt.bob.mts7.core;

import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;

import no.entur.tlv.parser.LenientTlvPullParser;

/**
 * Enrich a card with the data of the select application response: the application identifier (version, participant identifier and serial), which is required,
 * and the signature counter, the lifecycle status and the maximum APDU lengths, if present.
 * <p>
 * The response comes from the card, so anything wrong with it is a problem on the card side: {@linkplain InvalidCardMts7Exception}. The parsing never fails
 * with any other exception.
 * <p>
 * Instances are thread safe, so a single instance can be shared by all threads. The cards are not, so a card must only be enriched by one thread at a time.
 */

public class Mts7CardEnricher {

	public static final int FILE_MANAGEMENT_TEMPLATE = 0x64;
	public static final int APPLICATION_RELATED_DATA = 0x6E;
	public static final int APPLICATION_IDENTIFIER = 0x4F;
	public static final int SECURITY_SUPPORT_DATA = 0x7A;
	public static final int LIFECYCLE_STATUS_BYTE = 0x8A;
	public static final int DIGITAL_SIGNATURE_COUNTER = 0x93;
	public static final int EXTENDED_LENGTH_INFORMATION = 0x7F66;
	public static final int MAXIMUM_APDU_LENGTH = 0x02;
	public static final int CARDHOLDER_CERTIFICATES = 0x7F21;

	/**
	 * Length of the application identifier: the 6 bytes of the AID (A0 00 00 07 81 01) which precede the version (1 byte), the participant identifier (2 bytes)
	 * and the serial (7 bytes).
	 */

	protected static final int APPLICATION_IDENTIFIER_LENGTH = 6 + 1 + 2 + 7;

	/**
	 * Enrich the card with the payload of the select application response.
	 *
	 * @param card                             the card
	 * @param selectApplicationResponsePayload response payload, without the status word
	 * @throws InvalidCardMts7Exception if the response is malformed, or has no valid application identifier (a problem on the card side)
	 */

	public void enrichSelectApplicationResponsePayload(Mts7Card card, byte[] selectApplicationResponsePayload) throws InvalidCardMts7Exception {
		enrich(card, selectApplicationResponsePayload, false);
	}

	/**
	 * Enrich the card with the select application response.
	 *
	 * @param card                      the card
	 * @param selectApplicationResponse response APDU, with the status word
	 * @throws InvalidCardMts7Exception if the response is malformed, or has no valid application identifier (a problem on the card side)
	 */

	public void enrichSelectApplicationResponseApdu(Mts7Card card, byte[] selectApplicationResponse) throws InvalidCardMts7Exception {
		enrich(card, selectApplicationResponse, true);
	}

	protected void enrich(Mts7Card card, byte[] response, boolean apdu) throws InvalidCardMts7Exception {
		boolean applicationIdentifier;
		try {
			// the parser is stateful, and cheap to create
			LenientTlvPullParser pullParser = new LenientTlvPullParser();
			if (apdu) {
				pullParser.setResponseApduPayload(response);
			} else {
				pullParser.setBuffer(response);
			}
			applicationIdentifier = parse(card, pullParser);
		} catch (RuntimeException e) {
			// the parsing is lenient, so this is not expected; whatever is wrong with the response, it came from the card
			throw new InvalidCardMts7Exception("Malformed select application response", e);
		}
		if (!applicationIdentifier) {
			throw new InvalidCardMts7Exception("Missing or malformed application identifier in the select application response");
		}
	}

	/**
	 * @return whether a valid application identifier was found
	 */

	protected boolean parse(Mts7Card card, LenientTlvPullParser pullParser) {
		boolean applicationIdentifier = false;
		do {
			int tag = pullParser.nextTag();
			if (tag == -1) {
				break;
			}

			if (tag == FILE_MANAGEMENT_TEMPLATE) {
				applicationIdentifier |= parseFileManagementData(card, pullParser.parseTagLengthValuePayload());
			}
		} while (true);
		return applicationIdentifier;
	}

	/**
	 * @return whether a valid application identifier was found
	 */

	public boolean parseFileManagementData(Mts7Card card, LenientTlvPullParser payloadParser) {
		boolean applicationIdentifier = false;
		do {
			int tag = payloadParser.nextTag();
			if (tag == -1) {
				break;
			}

			if (tag == APPLICATION_RELATED_DATA) {
				applicationIdentifier |= parseApplicationRelatedData(card, payloadParser.parseTagLengthValuePayload());
			}
		} while (true);
		return applicationIdentifier;
	}

	/**
	 * @return whether a valid application identifier was found
	 */

	protected boolean parseApplicationRelatedData(Mts7Card card, LenientTlvPullParser payloadParser) {
		boolean applicationIdentifier = false;
		do {
			int tag = payloadParser.nextTag();
			if (tag == -1) {
				break;
			}
			switch (tag) {
			case APPLICATION_IDENTIFIER: {
				byte[] payload = payloadParser.getPayload();

				if (payload.length < APPLICATION_IDENTIFIER_LENGTH) {
					// too short to contain the version, participant identifier and serial; ignore it
					break;
				}

				// Version – This version, one byte; 0x01
				int version = payload[6] & 0xFF;

				// PID – Participant Identifier, two bytes, big endian byte order
				int pid = ((payload[7] & 0xFF) << 8) + (payload[8] & 0xFF);

				// Serial – Serial number of the PICC, 7 bytes. 7 bytes. It set by the issuer and SHOULD be discontinuous to
				// preclude guessing. . The serial number MAY be printed on the token and used as a reference for
				// the token. In the conversion between the byte and integer format, big endian byte order SHALL be
				// used.

				byte[] serial = new byte[7];
				System.arraycopy(payload, 9, serial, 0, 7);

				card.setVersion(version);
				card.setParticipantIdentifier(pid);
				card.setSerial(serial);

				applicationIdentifier = true;
				break;
			}
			case SECURITY_SUPPORT_DATA: {
				parseSecuritySupportData(card, payloadParser.parseTagLengthValuePayload());
				break;
			}
			case LIFECYCLE_STATUS_BYTE: {
				if (payloadParser.getBufferPayloadLength() < 1) {
					// there is no status byte; the byte at the offset belongs to something else
					break;
				}
				int code = payloadParser.getBuffer()[payloadParser.getBufferPayloadOffset()] & 0xFF;

				card.setLifeCycleStatus(LifecycleStatus.parse(code));

				break;
			}
			case EXTENDED_LENGTH_INFORMATION: {
				parseExtendedLengthInformation(card, payloadParser.parseTagLengthValuePayload());

				break;
			}
			}

		} while (true);
		return applicationIdentifier;
	}

	private void parseSecuritySupportData(Mts7Card card, LenientTlvPullParser payloadParser) {
		do {
			int tag = payloadParser.nextTag();
			if (tag == -1) {
				break;
			}
			switch (tag) {
			case DIGITAL_SIGNATURE_COUNTER: {
				int value = readNumberPayload(payloadParser);

				card.setSignatureCounter(value);
				break;
			}
			}
		} while (true);
	}

	private void parseExtendedLengthInformation(Mts7Card card, LenientTlvPullParser payloadParser) {
		do {
			int tag = payloadParser.nextTag();
			if (tag == -1) {
				break;
			}
			switch (tag) {
			case MAXIMUM_APDU_LENGTH: {
				int value = readNumberPayload(payloadParser);

				if (card.hasMaximumCommandApduLength()) {
					card.setMaximumResponseApduLength(value);
				} else {
					card.setMaximumCommandApduLength(value);
				}
				break;
			}
			}
		} while (true);
	}

	private int readNumberPayload(LenientTlvPullParser payloadParser) {
		byte[] buffer = payloadParser.getBuffer();

		int length = payloadParser.getBufferPayloadLength();

		int value = 0;
		for (int i = length - 1; i >= 0; i--) {
			int v = buffer[payloadParser.getBufferPayloadOffset() + i] & 0xFF;
			int shift = length - 1 - i;

			value += (v << (8 * shift));
		}
		return value;
	}

}
