package no.entur.abt.bob.mts7.test.record.bob;

import java.io.CharArrayWriter;
import java.io.Closeable;
import java.io.IOException;
import java.util.Map;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.MappingJsonFactory;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;
import no.entur.abt.bob.mts7.utils.ResponseApduStatusCodes;
import no.entur.abt.bob.mts7.utils.nfc.Card;
import no.entur.tlv.utils.TlvPrettyPrinter;

/**
 * 
 * A card that print TLV details.
 * 
 * Attempts to minimize number of log statements.
 */

public class Mts7PrettyPrinterCard implements no.entur.abt.bob.mts7.utils.nfc.Card, Closeable {

	private static final Logger LOGGER = LoggerFactory.getLogger(Mts7PrettyPrinterCard.class);

	public static Builder newBuilder() {
		return new Builder();
	}

	public static class Builder {

		private Card card;
		private TlvPrettyPrinter prettyPrinter;
		private boolean silent = false;

		public Builder withSilent(boolean silent) {
			this.silent = silent;
			return this;
		}

		public Builder withPrettyPrinter(TlvPrettyPrinter prettyPrinter) {
			this.prettyPrinter = prettyPrinter;
			return this;
		}

		public Builder withCard(Card card) {
			this.card = card;
			return this;
		}

		public Mts7PrettyPrinterCard build() {
			Mts7PrettyPrintCardRecordingAnalyzer analyzer = new Mts7PrettyPrintCardRecordingAnalyzer(prettyPrinter);

			return new Mts7PrettyPrinterCard(card, analyzer, silent);
		}

	}

	protected final Card card;

	protected Mts7PrettyPrintCardRecordingAnalyzer analyzer;

	protected boolean silent;

	protected final JsonFactory jsonFactory = new MappingJsonFactory();
	protected final CBORMapper mapper = new CBORMapper();

	public Mts7PrettyPrinterCard(Card card, Mts7PrettyPrintCardRecordingAnalyzer analyzer, boolean silent) {
		this.card = card;
		this.analyzer = analyzer;
		this.silent = silent;
	}

	@Override
	public void close() throws IOException {
		if (card instanceof Closeable) {
			Closeable closable = (Closeable) card;
			closable.close();
		}
	}

	@Override
	public byte[] transceive(byte[] data) throws IOException {
		long time = System.currentTimeMillis();

		StringBuilder commandStringBuilder = new StringBuilder("-> ");

		Mts7CardCommandType command = analyzer.processCommand(data);

		switch (command) {
		case SELECT_APPLICATION: {
			commandStringBuilder.append(command.getName());
			commandStringBuilder.append(" '");
			commandStringBuilder.append(analyzer.getApplicationId().toString());
			commandStringBuilder.append("'");
			break;
		}
		default: {
			Integer participantIdentifier = analyzer.getParticipantIdentifier();
			if (participantIdentifier != null) {
				commandStringBuilder.append(String.format("%02x", (participantIdentifier.intValue() >> 8) & 0xFF).toUpperCase());
				commandStringBuilder.append(String.format("%02x", participantIdentifier.intValue() & 0xFF).toUpperCase());
				commandStringBuilder.append(":");
			}
			byte[] serial = analyzer.getSerial();
			if (serial != null) {
				commandStringBuilder.append(ByteArrayHexStringConverter.toHexString(serial));
				commandStringBuilder.append(":");
			}
			commandStringBuilder.append(command.getName());
		}
		}
		commandStringBuilder.append(": ");

		commandStringBuilder.append(ByteArrayHexStringConverter.toHexString(data));

		if (!silent) {
			LOGGER.info(commandStringBuilder.toString());
		}

		byte[] response = card.transceive(data);

		long duration = System.currentTimeMillis() - time;

		if (!silent) {
			String responseCode = ResponseApduStatusCodes.getResponseCode(response);

			switch (command) {
			case SELECT_APPLICATION: {
				String responseAPDU = analyzer.getPrettyPrinter().responseAPDU(response);
				if (responseCode != null) {
					LOGGER.info(
							"<- " + responseCode + " :" + ByteArrayHexStringConverter.toHexString(response) + " (in " + (duration) + "ms) \n" + responseAPDU);
				} else {
					LOGGER.info("<- " + ByteArrayHexStringConverter.toHexString(response) + " (in " + (duration) + "ms) \n" + responseAPDU);
				}

				break;
			}
			case GET_NEXT_DATA_COMMAND: {
				if (!isReferenceNotFound(response)) {
					byte[] payload = new byte[response.length - 2];
					if (payload.length > 0) {
						CharArrayWriter writer = new CharArrayWriter(512);

						JsonGenerator generator = jsonFactory.createGenerator(writer).useDefaultPrettyPrinter();

						generator.writeStartObject();

						System.arraycopy(response, 0, payload, 0, payload.length);
						Map<String, Object> otherValue = mapper.readValue(payload, Map.class);

						for (Entry<String, Object> entry : otherValue.entrySet()) {

							String key = entry.getKey();
							switch (key) {
							case "v": {
								byte[] v = (byte[]) entry.getValue();
								String majorVersion = mapper.readValue(v, String.class);

								generator.writeStringField("v", majorVersion);

								break;
							}
							case "p": {

								// A header object that provides the required metadata for the signature
								// SHALL be attached to the Ticket Bundle by CBOR encoding each of the objects separately, joining
								// them in a CBOR array. This CBOR array is then used as input to the signing function, adding the
								// output of the signing function as the last element to the CBOR array. This forms the Issuer Signed
								// Ticket Bundle.

								byte[] p = (byte[]) entry.getValue();
								byte[][] a = mapper.readValue(p, byte[][].class);

								generator.writeFieldName("p");
								generator.writeStartArray();

								for (int i = 0; i < a.length - 1; i++) {
									Map<String, Object> m = mapper.readValue(a[i], Map.class);

									generator.writeObject(m);
								}

								byte[] signature = a[a.length - 1];
								generator.writeString(ByteArrayHexStringConverter.toHexString(signature));

								generator.writeEndArray();

								break;
							}
							default: {
								generator.writeObjectField(entry.getKey(), entry.getValue());
							}
							}
						}

						generator.writeEndObject();
						generator.flush();

						LOGGER.info("<- " + ByteArrayHexStringConverter.toHexString(response) + " (in " + (duration) + "ms)\n" + writer.toString());
					} else {
						LOGGER.info("<- " + ByteArrayHexStringConverter.toHexString(response) + " (in " + (duration) + "ms)\n");
					}
				}

				break;
			}
			default: {
				LOGGER.info("<- " + ByteArrayHexStringConverter.toHexString(response) + " (in " + (duration) + "ms)");
				break;
			}
			}
		}

		if (response != null) {
			analyzer.processResponse(response);
		}

		return response;
	}

	private boolean isReferenceNotFound(byte[] response) {
		// If a next instance of the DO does not exist, response should be empty and SW1-SW2 set to '6A 88' (Referenced data not found).
		// '6A 88'
		return (response[response.length - 2] & 0xFF) == 0x6A || (response[response.length - 1] & 0xFF) == 0x88;
	}

	public Logger getLogger() {
		return LOGGER;
	}

}
