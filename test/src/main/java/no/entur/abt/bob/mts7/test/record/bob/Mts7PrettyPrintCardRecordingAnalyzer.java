package no.entur.abt.bob.mts7.test.record.bob;

import java.io.IOException;

import no.entur.abt.bob.mts7.utils.nfc.ApplicationIdentifier;
import no.entur.abt.bob.mts7.utils.nfc.DefaultApplicationIdentifier;
import no.entur.tlv.parser.LenientTlvPullParser;
import no.entur.tlv.utils.TlvPrettyPrinter;

public class Mts7PrettyPrintCardRecordingAnalyzer extends Mts7CardRecordingAnalyzer implements Mts7CardRecordingAnalyzer.Listener {

	public static final int FILE_MANAGEMENT_TEMPLATE = 0x64;
	public static final int APPLICATION_RELATED_DATA = 0x6E;
	public static final int APPLICATION_IDENTIFIER = 0x4F;

	private final LenientTlvPullParser tlvParser = new LenientTlvPullParser();

	private Integer participantIdentifier;
	private Integer version;
	private byte[] serial;

	private TlvPrettyPrinter prettyPrinter;
	private ApplicationIdentifier applicationId;

	public Mts7PrettyPrintCardRecordingAnalyzer(TlvPrettyPrinter prettyPrinter) {
		this.prettyPrinter = prettyPrinter;

		this.listener = this;
	}

	@Override
	public void onSelectApplicationCommand(byte[] commandApdu) throws IOException {
		byte[] data = new byte[commandApdu[4] & 0xFF];
		System.arraycopy(commandApdu, 5, data, 0, data.length);

		applicationId = new DefaultApplicationIdentifier(data);
	}

	@Override
	public void onSelectApplicationResponse(byte[] responseApdu) throws IOException {
		tlvParser.setResponseApduPayload(responseApdu);
		LenientTlvPullParser fciTemplate = tlvParser.parseTagLengthValuePayload(FILE_MANAGEMENT_TEMPLATE);
		if (fciTemplate != null) {
			LenientTlvPullParser applicationRelatedData = fciTemplate.parseTagLengthValuePayload(APPLICATION_RELATED_DATA);
			if (applicationRelatedData != null) {
				if (applicationRelatedData.skipTo(APPLICATION_IDENTIFIER)) {

					byte[] payload = applicationRelatedData.getPayload();

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

					this.version = version;
					this.participantIdentifier = pid;
					this.serial = serial;
				}
			}
		}
	}

	@Override
	public void onGetNextDataCommand(byte[] commandApdu) throws IOException {

	}

	@Override
	public void onGetNextDataResponse(byte[] responseApdu) throws IOException {
		tlvParser.setResponseApduPayload(responseApdu);
	}

	@Override
	public void onInternalAuthenticateCommand(byte[] commandApdu) throws IOException {

	}

	@Override
	public void onInternalAuthenticateResponse(byte[] responseApdu) throws IOException {

	}

	public TlvPrettyPrinter getPrettyPrinter() {
		return prettyPrinter;
	}

	public ApplicationIdentifier getApplicationId() {
		return applicationId;
	}

	public byte[] getSerial() {
		return serial;
	}

	public Integer getVersion() {
		return version;
	}

	public Integer getParticipantIdentifier() {
		return participantIdentifier;
	}

	public void reset() {
		participantIdentifier = null;
		version = null;
		serial = null;

		applicationId = null;
	}
}
