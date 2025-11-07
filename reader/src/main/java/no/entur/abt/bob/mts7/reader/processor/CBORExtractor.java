package no.entur.abt.bob.mts7.reader.processor;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

public class CBORExtractor {

	protected final CBORMapper cborMapper;

	public CBORExtractor(CBORMapper cborMapper) {
		this.cborMapper = cborMapper;
	}

	public String parseAlgorithm(byte[] content) throws IOException {
		JsonParser parser = cborMapper.createParser(content);
		try {
			JsonToken nextToken = parser.nextToken();
			if (nextToken != JsonToken.START_OBJECT) {
				throw new IOException("Expected start object");
			}
			do {
				if (nextToken == JsonToken.FIELD_NAME && "p".equals(parser.currentName())) {
					parser.nextToken();

					return extractAlgorithmFromArray(parser.getBinaryValue());
				}
				nextToken = parser.nextToken();
			} while (nextToken != null);
			return null;
		} finally {
			parser.close();
		}
	}

	protected String extractAlgorithmFromArray(byte[] content) throws IOException {
		// parse all except the last, which is the signature
		byte[] previous = null;

		// expect array of byte arrays

		JsonParser parser = cborMapper.createParser(content);
		try {
			JsonToken nextToken = parser.nextToken();
			if (nextToken != JsonToken.START_ARRAY) {
				throw new IOException("Expected start array");
			}

			do {
				if (nextToken.isScalarValue()) {
					if (previous != null) {
						String algorithm = extractAlgorithm(previous);
						if (algorithm != null) {
							return algorithm;
						}
					}
					previous = parser.getBinaryValue();
				}
				nextToken = parser.nextToken();
			} while (nextToken != null);
			return null;
		} finally {
			parser.close();
		}
	}

	protected String extractAlgorithm(byte[] content) throws IOException {
		JsonParser parser = cborMapper.createParser(content);
		try {
			JsonToken nextToken = parser.nextToken();
			if (nextToken != JsonToken.START_OBJECT) {
				throw new IOException("Expected start object");
			}

			int level = 1;
			do {
				nextToken = parser.nextToken();

				if (nextToken == JsonToken.START_OBJECT) {
					level++;
				} else if (nextToken == JsonToken.END_OBJECT) {
					level--;
				} else if (level == 1) {
					if (nextToken == JsonToken.FIELD_NAME) {
						if ("did".equals(parser.currentName())) {
							return null;
						}
						if ("alg".equals(parser.currentName())) {
							return parser.nextTextValue();
						}
					}
				}
			} while (level > 0);
			return null;
		} finally {
			parser.close();
		}
	}

}
