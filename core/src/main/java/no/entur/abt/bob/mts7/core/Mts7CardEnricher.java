package no.entur.abt.bob.mts7.core;

import no.entur.tlv.parser.LenientTlvPullParser;

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

	protected final LenientTlvPullParser pullParser = new LenientTlvPullParser();

	public void enrichSelectApplicationResponsePayload(Mts7Card card, byte[] selectApplicationResponsePayload) {
		pullParser.setBuffer(selectApplicationResponsePayload);

		do {
			int tag = pullParser.nextTag();
			if (tag == -1) {
				break;
			}

			if (tag == FILE_MANAGEMENT_TEMPLATE) {
				parseFileManagementData(card, pullParser.parseTagLengthValuePayload());
			}
		} while (true);
	}

	public void enrichSelectApplicationResponseApdu(Mts7Card card, byte[] selectApplicationResponse) {
		pullParser.setResponseApduPayload(selectApplicationResponse);

		do {
			int tag = pullParser.nextTag();
			if (tag == -1) {
				break;
			}

			if (tag == FILE_MANAGEMENT_TEMPLATE) {
				parseFileManagementData(card, pullParser.parseTagLengthValuePayload());
			}
		} while (true);
	}

	public void parseFileManagementData(Mts7Card card, LenientTlvPullParser payloadParser) {
		do {
			int tag = payloadParser.nextTag();
			if (tag == -1) {
				break;
			}

			if (tag == APPLICATION_RELATED_DATA) {
				parseApplicationRelatedData(card, payloadParser.parseTagLengthValuePayload());
			}
		} while (true);
	}

	protected void parseApplicationRelatedData(Mts7Card card, LenientTlvPullParser payloadParser) {
		do {
			int tag = payloadParser.nextTag();
			if (tag == -1) {
				break;
			}
			switch (tag) {
			case APPLICATION_IDENTIFIER: {
				byte[] payload = payloadParser.getPayload();

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

				break;
			}
			case SECURITY_SUPPORT_DATA: {
				parseSecuritySupportData(card, payloadParser.parseTagLengthValuePayload());
				break;
			}
			case LIFECYCLE_STATUS_BYTE: {
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
