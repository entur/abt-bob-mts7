package no.entur.abt.bob.mts7.utils;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

public class ResponseApduStatusCodes {

	private static class Filter {

		private final int letter0; // MSD
		private final int letter1;
		private final int letter2;
		private final int letter3; // LSD

		private final String description;

		public Filter(int letter0, int letter1, int letter2, int letter3, final String description) {
			super();
			this.letter0 = letter0;
			this.letter1 = letter1;
			this.letter2 = letter2;
			this.letter3 = letter3;
			this.description = description;
		}

		public int matches(byte a, byte b) {
			int matches = 0;
			if (letter0 != -1) {
				int a0 = (a >> 4) & 0xF;
				if (a0 == letter0) {
					matches++;
				}
			}
			if (letter1 != -1) {
				int a1 = a & 0xF;
				if (a1 == letter1) {
					matches++;
				}
			}
			if (letter2 != -1) {
				int b0 = (b >> 4) & 0xF;
				if (b0 == letter2) {
					matches++;
				}
			}
			if (letter3 != -1) {
				int b1 = b & 0xF;
				if (b1 == letter3) {
					matches++;
				}
			}
			return matches;
		}

		public String getDescription() {
			return description;
		}
	}

	private static final List<Filter> FILTERS;
	static {
		try {
			InputStream is = ResponseApduStatusCodes.class.getResourceAsStream("/bob/responses.csv");
			InputStreamReader reader = new InputStreamReader(is, StandardCharsets.UTF_8);

			List<Filter> filters = new ArrayList<>();

			CSVParser parser = CSVParser.parse(reader, CSVFormat.RFC4180);
			for (CSVRecord csvRecord : parser) {
				String a = csvRecord.get(0);
				String b = csvRecord.get(1);

				String description = csvRecord.get(3);

				if (a.length() != 2) {
					continue;
				}

				int a0;
				if (isHex(a.charAt(0))) {
					a0 = parseHex(a.charAt(0));
				} else {
					a0 = -1;
				}

				int a1;
				if (isHex(a.charAt(1))) {
					a1 = parseHex(a.charAt(1));
				} else {
					a1 = -1;
				}

				int b0;
				int b1;
				if (b.length() != 2) {
					b0 = -1;
					b1 = -1;
				} else {
					if (isHex(b.charAt(0))) {
						b0 = parseHex(b.charAt(0));
					} else {
						b0 = -1;
					}

					if (isHex(b.charAt(1))) {
						b1 = parseHex(b.charAt(1));
					} else {
						b1 = -1;
					}
				}

				filters.add(new Filter(a0, a1, b0, b1, description));
			}

			FILTERS = filters;
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	public static boolean isHex(char c) {
		return Character.isDigit(c) || 'A' <= c && c <= 'F';
	}

	public static int parseHex(char c) {
		if (Character.isDigit(c)) {
			return c - '0';
		}
		return 10 + c - 'A';
	}

	public static String getResponseCode(byte[] responseApdu) {
		byte a = responseApdu[responseApdu.length - 2];
		byte b = responseApdu[responseApdu.length - 1];

		int bestScore = 0;
		Filter best = null;

		for (Filter filter : FILTERS) {
			int matches = filter.matches(a, b);
			if (matches == 0) {
				continue;
			}
			if (matches > bestScore) {
				best = filter;
				bestScore = matches;
			}
		}
		if (best != null) {
			return best.description;
		}
		return null;
	}

}
