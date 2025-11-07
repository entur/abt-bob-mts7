package no.entur.abt.bob.mts7.test.record;

import java.io.IOException;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class CardInvocationDeserializer extends StdDeserializer<CardInvocation> {

	private static final long serialVersionUID = 1L;

	public CardInvocationDeserializer() {
		super(CardInvocationSerializer.class);
	}

	@Override
	public CardInvocation deserialize(JsonParser parser, DeserializationContext ctxt) throws IOException, JacksonException {

		if (JsonToken.START_OBJECT != parser.getCurrentToken()) {
			throw new IllegalStateException();
		}

		String nextFieldName = parser.nextFieldName();
		if (!nextFieldName.equals("type")) {
			throw new RuntimeException();
		}

		JsonToken nextToken = parser.nextToken();
		if (nextToken != JsonToken.VALUE_STRING) {
			throw new RuntimeException();
		}

		String type = parser.getText();

		switch (type) {
		case "transceive": {
			return parseTransceive(parser);
		}
		case "connect": {
			return parseConnect(parser);
		}
		case "close": {
			return parseClose(parser);
		}
		default:
			throw new IllegalStateException();
		}
	}

	private CardInvocation parseClose(JsonParser parser) throws IOException {
		CloseInvocation invocation = new CloseInvocation();

		JsonToken nextToken = parser.nextToken();
		while (nextToken == JsonToken.FIELD_NAME) {
			String fieldName = parser.currentName();

			nextToken = parser.nextToken();
			if (!nextToken.isScalarValue()) {
				throw new IllegalStateException();
			}
			setField(fieldName, parser, invocation);

			nextToken = parser.nextToken();
		}

		if (parser.currentToken() != JsonToken.END_OBJECT) {
			throw new IllegalStateException("Got " + parser.currentToken());
		}

		return invocation;
	}

	private CardInvocation parseConnect(JsonParser parser) throws IOException {
		ConnectInvocation invocation = new ConnectInvocation();

		JsonToken nextToken = parser.nextToken();
		while (nextToken == JsonToken.FIELD_NAME) {
			String fieldName = parser.currentName();

			nextToken = parser.nextToken();
			if (!nextToken.isScalarValue()) {
				throw new IllegalStateException();
			}
			setField(fieldName, parser, invocation);

			nextToken = parser.nextToken();
		}

		if (parser.currentToken() != JsonToken.END_OBJECT) {
			throw new IllegalStateException("Got " + parser.currentToken());
		}

		return invocation;
	}

	private CardInvocation parseTransceive(JsonParser parser) throws IOException {
		TransceiveInvocation invocation = new TransceiveInvocation();

		JsonToken nextToken = parser.nextToken();
		while (nextToken == JsonToken.FIELD_NAME) {
			String fieldName = parser.currentName();
			nextToken = parser.nextToken();
			if (!nextToken.isScalarValue()) {
				throw new IllegalStateException();
			}

			switch (fieldName) {
			case "command": {

				String secretCommand = parser.getText();

				try {
					byte[] command = toCommandBytes(secretCommand);
					invocation.setCommand(command);
				} catch (Exception e) {
					throw new IOException(e);
				}

				break;
			}
			case "response": {

				String secretResponse = parser.getText();
				try {
					byte[] response = toResponseBytes(secretResponse);
					invocation.setResponse(response);
				} catch (Exception e) {
					throw new IOException(e);
				}

				break;
			}
			default: {
				setField(fieldName, parser, invocation);
				break;
			}
			}

			nextToken = parser.nextToken();
		}

		if (parser.currentToken() != JsonToken.END_OBJECT) {
			throw new IllegalStateException("Got " + parser.currentToken());
		}

		return invocation;
	}

	private void setField(String name, JsonParser parser, CardInvocation invocation) throws IOException {
		switch (name) {
		case "timestamp": {
			invocation.setTimestamp(parser.getLongValue());
			break;
		}
		case "duration": {
			invocation.setDuration(parser.getLongValue());
			break;
		}
		case "completed": {
			invocation.setCompleted(parser.getBooleanValue());
			break;
		}
		case "exception": {
			String text = parser.getText();
			if (text.equals(IOException.class.getName())) {
				invocation.setException(new IOException());
			} else {
				throw new IllegalStateException();
			}
			break;
		}
		}

	}

	// override to encrypt
	protected byte[] toCommandBytes(String secretCommand) {
		return ByteArrayHexStringConverter.hexStringToByteArray(secretCommand);
	}

	// override to encrypt
	protected byte[] toResponseBytes(String secretResponse) {
		return ByteArrayHexStringConverter.hexStringToByteArray(secretResponse);
	}

}
