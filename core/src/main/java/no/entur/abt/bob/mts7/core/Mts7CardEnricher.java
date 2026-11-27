package no.entur.abt.bob.mts7.core;

import java.util.Arrays;

import no.entur.abt.bob.mts7.api.InsufficientCardCommandsException;
import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.api.MalformedCardResponseException;
import no.entur.abt.bob.mts7.api.ReaderMts7Exception;

/**
 * Enrich a card with its application-related data (6E), from the select application response or from GET DATA of it: the application identifier (version,
 * participant identifier and serial), which is required, and the signature counter, the lifecycle status and the maximum APDU lengths, if present.
 * <p>
 * The data comes from the card, so anything wrong with it is a problem on the card side: {@linkplain InvalidCardMts7Exception}. That there is none is a problem
 * with the reader, which can always retrieve it: {@linkplain InsufficientCardCommandsException}. The parsing never fails with any other exception.
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

	// what was found of the application-related data (6E)
	private static final int NOT_FOUND = 0;
	private static final int INVALID = 1;
	private static final int VALID = 2;

	/**
	 * Enrich the card with its application-related data (6E): from the File Management Data in the select application response, or, as a card need not return
	 * it there (MTS7 section 4.1.1), from the response to GET DATA of it.
	 * <p>
	 * The card is only to blame when its application-related data is malformed, or has no valid application identifier. If the select application response has
	 * no application-related data, and there is no response to GET DATA of it, the reader did not retrieve it.
	 *
	 * @param card                             the card
	 * @param selectApplicationResponsePayload select application response payload, without the status word, possibly empty
	 * @param applicationRelatedDataPayload    response payload of GET DATA of the application-related data (6E), without the status word, or null if none
	 * @throws InvalidCardMts7Exception          if the application-related data of the card is malformed, or has no valid application identifier (a problem on
	 *                                           the card side)
	 * @throws InsufficientCardCommandsException if there is no application-related data, as the reader did not retrieve it (a problem with the reader)
	 */

	public void enrich(Mts7Card card, byte[] selectApplicationResponsePayload, byte[] applicationRelatedDataPayload)
			throws InvalidCardMts7Exception, InsufficientCardCommandsException {
		int fromSelect = NOT_FOUND;
		RuntimeException selectFailure = null;
		boolean malformedSelect = false;
		if (selectApplicationResponsePayload != null) {
			try {
				fromSelect = parseTemplates(card, selectApplicationResponsePayload);
			} catch (RuntimeException e) {
				// not expected
				selectFailure = e;
			}
			malformedSelect = selectFailure != null || !isWellFormed(selectApplicationResponsePayload);
		}
		if (fromSelect == VALID) {
			return;
		}
		if (fromSelect == INVALID) {
			throw new InvalidCardMts7Exception("Missing or malformed application identifier in the select application response");
		}
		if (applicationRelatedDataPayload != null) {
			// the response is the TLV coded 6E (MTS7 section 4.1.2)
			if (parse(card, applicationRelatedDataPayload, "application-related data") != VALID) {
				throw new InvalidCardMts7Exception("Missing or malformed application identifier in the application-related data");
			}
			return;
		}
		if (malformedSelect) {
			// whatever is wrong with the response, it came from the card
			throw new InvalidCardMts7Exception("Malformed select application response", selectFailure);
		}
		// empty, or without the application-related data, which the card need not return here
		throw new InsufficientCardCommandsException(
				"No application-related data (6E) in the select application response, and no GET DATA of it (MTS7 section 4.1.1)");
	}

	/**
	 * Enrich the card with the payload of the select application response alone.
	 *
	 * @param card                             the card
	 * @param selectApplicationResponsePayload response payload, without the status word
	 * @throws InvalidCardMts7Exception          if the application-related data in the response is malformed, or has no valid application identifier (a problem
	 *                                           on the card side)
	 * @throws InsufficientCardCommandsException if the response has no application-related data, which the reader then should have retrieved with GET DATA
	 */

	public void enrichSelectApplicationResponsePayload(Mts7Card card, byte[] selectApplicationResponsePayload)
			throws InvalidCardMts7Exception, InsufficientCardCommandsException {
		enrich(card, selectApplicationResponsePayload, null);
	}

	/**
	 * Enrich the card with the select application response alone.
	 *
	 * @param card                      the card
	 * @param selectApplicationResponse response APDU, with the status word
	 * @throws InvalidCardMts7Exception if the application-related data in the response is malformed, or has no valid application identifier (a problem on the
	 *                                  card side)
	 * @throws ReaderMts7Exception      if the response has no application-related data, which the reader then should have retrieved with GET DATA
	 *                                  ({@linkplain InsufficientCardCommandsException}), or is shorter than its status word
	 *                                  ({@linkplain MalformedCardResponseException})
	 */

	public void enrichSelectApplicationResponseApdu(Mts7Card card, byte[] selectApplicationResponse) throws InvalidCardMts7Exception, ReaderMts7Exception {
		if (selectApplicationResponse == null || selectApplicationResponse.length < 2) {
			// a card always responds with a status word
			throw new MalformedCardResponseException(
					"Malformed select application response: " + (selectApplicationResponse == null ? "missing" : selectApplicationResponse.length + " bytes"));
		}
		enrich(card, Arrays.copyOf(selectApplicationResponse, selectApplicationResponse.length - 2), null);
	}

	/**
	 * @return whether, and how, the application-related data was found
	 */

	protected int parse(Mts7Card card, byte[] payload, String what) throws InvalidCardMts7Exception {
		try {
			return parseTemplates(card, payload);
		} catch (RuntimeException e) {
			// not expected; whatever is wrong with the response, it came from the card
			throw new InvalidCardMts7Exception("Malformed " + what, e);
		}
	}

	/**
	 * Reads BER-TLV data objects one at a time, skipping padding ('00' or 'FF') before, between and after them (ISO/IEC 7816-4 section 5.2.2), as a reader
	 * does. It stops at the first data object which is malformed.
	 */

	protected static final class DataObjectReader {

		private static final int MAXIMUM_TAG_BYTES = 3;

		private final byte[] data;
		private final int end;
		private int position;

		private int tag;
		private int valueOffset;
		private int valueLength;
		private boolean malformed;

		public DataObjectReader(byte[] data, int offset, int end) {
			this.data = data;
			this.position = offset;
			this.end = end;
		}

		/**
		 * @return true if there is another data object, false at the end or at a data object which is malformed (see {@linkplain #isMalformed()})
		 */

		public boolean next() {
			while (position < end && (data[position] == 0x00 || data[position] == (byte) 0xFF)) {
				position++;
			}
			if (position >= end) {
				return false;
			}
			int i = position;
			int t = data[i++] & 0xFF;
			if ((t & 0x1F) == 0x1F) {
				// subsequent tag bytes, the last one with b8 = 0
				int count = 0;
				int b;
				do {
					if (i >= end || ++count > MAXIMUM_TAG_BYTES) {
						return malformed();
					}
					b = data[i++] & 0xFF;
					t = (t << 8) | b;
				} while ((b & 0x80) != 0);
			}
			if (i >= end) {
				return malformed();
			}
			int first = data[i++] & 0xFF;
			long length;
			if (first < 0x80) {
				length = first;
			} else {
				int count = first & 0x7F;
				if (count == 0 || count > 4 || count > end - i) {
					return malformed();
				}
				length = 0;
				for (int k = 0; k < count; k++) {
					length = (length << 8) | (data[i++] & 0xFF);
				}
			}
			if (length > end - i) {
				return malformed();
			}
			tag = t;
			valueOffset = i;
			valueLength = (int) length;
			position = i + valueLength;
			return true;
		}

		private boolean malformed() {
			malformed = true;
			position = end;
			return false;
		}

		public int getTag() {
			return tag;
		}

		public int getValueOffset() {
			return valueOffset;
		}

		public int getValueLength() {
			return valueLength;
		}

		public int getValueEnd() {
			return valueOffset + valueLength;
		}

		public boolean isMalformed() {
			return malformed;
		}
	}

	/**
	 * Check that data is a sequence of complete BER-TLV data objects, possibly with padding ('00' or 'FF') before, between or after them (ISO/IEC 7816-4
	 * section 5.2.2). Only the outermost data objects are checked.
	 *
	 * @param data the data
	 * @return whether the data is well-formed
	 */

	static boolean isWellFormed(byte[] data) {
		DataObjectReader reader = new DataObjectReader(data, 0, data.length);
		while (reader.next()) {
			// check them all
		}
		return !reader.isMalformed();
	}

	/**
	 * Parse the File Management Data (64) with the application-related data (6E) in it, or the application-related data itself.
	 *
	 * @return whether, and how, the application-related data was found
	 */

	protected int parseTemplates(Mts7Card card, byte[] data) {
		int status = NOT_FOUND;
		DataObjectReader reader = new DataObjectReader(data, 0, data.length);
		while (reader.next()) {
			if (reader.getTag() == FILE_MANAGEMENT_TEMPLATE) {
				status = Math.max(status, parseFileManagementTemplate(card, data, reader.getValueOffset(), reader.getValueEnd()));
			} else if (reader.getTag() == APPLICATION_RELATED_DATA) {
				status = Math.max(status, parseApplicationRelatedData(card, data, reader.getValueOffset(), reader.getValueEnd()) ? VALID : INVALID);
			}
		}
		return status;
	}

	private int parseFileManagementTemplate(Mts7Card card, byte[] data, int offset, int end) {
		int status = NOT_FOUND;
		DataObjectReader reader = new DataObjectReader(data, offset, end);
		while (reader.next()) {
			if (reader.getTag() == APPLICATION_RELATED_DATA) {
				status = Math.max(status, parseApplicationRelatedData(card, data, reader.getValueOffset(), reader.getValueEnd()) ? VALID : INVALID);
			}
		}
		return status;
	}

	/**
	 * Parse the value of the application-related data (6E).
	 *
	 * @param card   the card
	 * @param data   the data
	 * @param offset the start of the value
	 * @param end    the end of the value
	 * @return whether a valid application identifier was found
	 */

	protected boolean parseApplicationRelatedData(Mts7Card card, byte[] data, int offset, int end) {
		boolean applicationIdentifier = false;
		DataObjectReader reader = new DataObjectReader(data, offset, end);
		while (reader.next()) {
			int value = reader.getValueOffset();
			switch (reader.getTag()) {
			case APPLICATION_IDENTIFIER: {
				if (reader.getValueLength() < APPLICATION_IDENTIFIER_LENGTH) {
					// too short to contain the version, participant identifier and serial; ignore it
					break;
				}

				// Version – This version, one byte; 0x01
				int version = data[value + 6] & 0xFF;

				// PID – Participant Identifier, two bytes, big endian byte order
				int pid = ((data[value + 7] & 0xFF) << 8) + (data[value + 8] & 0xFF);

				// Serial – Serial number of the PICC, 7 bytes. It set by the issuer and SHOULD be discontinuous to preclude guessing. The serial number MAY be
				// printed on the token and used as a reference for the token. In the conversion between the byte and integer format, big endian byte order
				// SHALL be used.

				byte[] serial = Arrays.copyOfRange(data, value + 9, value + 16);

				card.setVersion(version);
				card.setParticipantIdentifier(pid);
				card.setSerial(serial);

				applicationIdentifier = true;
				break;
			}
			case SECURITY_SUPPORT_DATA: {
				parseSecuritySupportData(card, data, value, reader.getValueEnd());
				break;
			}
			case LIFECYCLE_STATUS_BYTE: {
				if (reader.getValueLength() < 1) {
					// there is no status byte
					break;
				}
				card.setLifeCycleStatus(LifecycleStatus.parse(data[value] & 0xFF));
				break;
			}
			case EXTENDED_LENGTH_INFORMATION: {
				parseExtendedLengthInformation(card, data, value, reader.getValueEnd());
				break;
			}
			default:
			}
		}
		return applicationIdentifier;
	}

	private void parseSecuritySupportData(Mts7Card card, byte[] data, int offset, int end) {
		DataObjectReader reader = new DataObjectReader(data, offset, end);
		while (reader.next()) {
			if (reader.getTag() == DIGITAL_SIGNATURE_COUNTER) {
				card.setSignatureCounter(readNumber(data, reader.getValueOffset(), reader.getValueLength()));
			}
		}
	}

	private void parseExtendedLengthInformation(Mts7Card card, byte[] data, int offset, int end) {
		DataObjectReader reader = new DataObjectReader(data, offset, end);
		while (reader.next()) {
			if (reader.getTag() == MAXIMUM_APDU_LENGTH) {
				int value = readNumber(data, reader.getValueOffset(), reader.getValueLength());

				if (card.hasMaximumCommandApduLength()) {
					card.setMaximumResponseApduLength(value);
				} else {
					card.setMaximumCommandApduLength(value);
				}
			}
		}
	}

	private static int readNumber(byte[] data, int offset, int length) {
		int value = 0;
		for (int i = 0; i < length; i++) {
			value = (value << 8) | (data[offset + i] & 0xFF);
		}
		return value;
	}

}
