package no.entur.abt.bob.mts7.test.record;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class CardInvocationSerializer extends StdSerializer<CardInvocation> {

	private static final long serialVersionUID = 1L;

	public CardInvocationSerializer() {
		super(CardInvocation.class);
	}

	@Override
	public void serialize(CardInvocation value, JsonGenerator writer, SerializerProvider provider) throws IOException, JsonProcessingException {

		writer.writeStartObject();

		if (value instanceof CloseInvocation) {
			CloseInvocation closeInvocation = (CloseInvocation) value;

			writer.writeStringField("type", "close");
		} else if (value instanceof TransceiveInvocation) {
			TransceiveInvocation transceiveInvocation = (TransceiveInvocation) value;

			writer.writeStringField("type", "transceive");

			byte[] command = transceiveInvocation.getCommand();

			String secretCommand;
			try {
				secretCommand = toCommandString(command);
			} catch (Exception e) {
				throw new IOException("Problem encrypting command", e);
			}

			writer.writeStringField("command", secretCommand);

			byte[] response = transceiveInvocation.getResponse();
			if (response != null) {
				String secretResponse;
				try {
					secretResponse = toResponseString(response);
				} catch (Exception e) {
					throw new IOException("Problem encrypting response", e);
				}

				writer.writeStringField("response", secretResponse);
			}
		} else if (value instanceof ConnectInvocation) {
			ConnectInvocation connectInvocation = (ConnectInvocation) value;

			writer.writeStringField("type", "connect");
		} else {
			throw new IllegalStateException();
		}

		writer.writeNumberField("timestamp", value.getTimestamp());
		writer.writeNumberField("duration", value.getDuration());
		writer.writeBooleanField("completed", value.isCompleted());

		Exception exception = value.getException();
		if (exception != null) {
			writer.writeStringField("exception", exception.getClass().getName());
		}

		writer.writeEndObject();
	}

	// override to encrypt
	protected String toCommandString(byte[] command) {
		return ByteArrayHexStringConverter.toHexString(command);
	}

	// override to encrypt
	protected String toResponseString(byte[] response) {
		return ByteArrayHexStringConverter.toHexString(response);
	}
}
