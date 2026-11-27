package no.entur.abt.bob.mts7.reader.processor;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.core.pki.Mts1Algorithms;

public class CBORExtractor {

	protected final CBORMapper cborMapper;

	public CBORExtractor(CBORMapper cborMapper) {
		this.cborMapper = cborMapper;
	}

	/**
	 * Extract the algorithm of the card from a GET DATA response, before it is processed: ES256 for an EC key, RS256 for an RSA key, from the type of the token
	 * public key in the Issuer Signature Protected Header (not from <code>alg</code>, which is the algorithm of the issuer signature).
	 *
	 * @param content the GET DATA response, without the status word
	 * @return the algorithm, or null if not found
	 * @throws IOException if the response is malformed
	 */

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

	/**
	 * Extract the algorithm of the card from the Issuer Signature Protected Header: from the type of the token public key (<code>kty</code> in
	 * <code>tpk</code>), not from <code>alg</code>, which is the algorithm of the issuer signature.
	 *
	 * @param content the (CBOR encoded) header
	 * @return ES256 for an EC key, RS256 for an RSA key, or null if this is not an Issuer Signature Protected Header, or it does not have a token public key of
	 *         a known type
	 * @throws IOException if the content is not a CBOR map, or is truncated
	 */

	protected String extractAlgorithm(byte[] content) throws IOException {
		JsonParser parser = cborMapper.createParser(content);
		try {
			JsonToken nextToken = parser.nextToken();
			if (nextToken != JsonToken.START_OBJECT) {
				throw new IOException("Expected start object");
			}

			int level = 1;
			// the level of the token public key, if in it
			int tpkLevel = -1;
			do {
				nextToken = parser.nextToken();

				if (nextToken == JsonToken.START_OBJECT) {
					level++;
				} else if (nextToken == JsonToken.END_OBJECT) {
					if (level == tpkLevel) {
						// a token public key without a type
						return null;
					}
					level--;
				} else if (nextToken == JsonToken.FIELD_NAME) {
					String name = parser.currentName();
					if (level == 1) {
						if ("did".equals(name)) {
							// the Device Signature Protected Header
							return null;
						}
						if ("tpk".equals(name)) {
							if (parser.nextToken() == JsonToken.START_OBJECT) {
								level++;
								tpkLevel = level;
							} else {
								// not a map
								return null;
							}
						}
					} else if (level == tpkLevel && "kty".equals(name)) {
						return Mts1Algorithms.getTokenAlgorithm(parser.nextTextValue());
					}
				}
			} while (level > 0);
			return null;
		} finally {
			parser.close();
		}
	}

}
