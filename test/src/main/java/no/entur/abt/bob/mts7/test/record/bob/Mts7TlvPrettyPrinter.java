package no.entur.abt.bob.mts7.test.record.bob;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

import no.entur.tlv.utils.ByteArrayKey;
import no.entur.tlv.utils.TlvPrettyPrinter;

public class Mts7TlvPrettyPrinter {

	private static final TlvPrettyPrinter INSTANCE;

	static {
		try {
			InputStream is = Mts7TlvPrettyPrinter.class.getResourceAsStream("/bob/tags.csv");
			InputStreamReader reader = new InputStreamReader(is, StandardCharsets.UTF_8);

			Set<ByteArrayKey> strings = new HashSet<>();

			Map<ByteArrayKey, String> tags = new HashMap<>();
			CSVParser parser = CSVParser.parse(reader, CSVFormat.RFC4180);
			for (CSVRecord csvRecord : parser) {
				String tag = csvRecord.get(0);
				String description = csvRecord.get(1);

				ByteArrayKey key = ByteArrayKey.create(tag);

				tags.put(key, description);
			}

			INSTANCE = TlvPrettyPrinter.newBuilder().withStrings(strings).withTags(tags).build();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static TlvPrettyPrinter getInstance() {
		return INSTANCE;
	}

}
