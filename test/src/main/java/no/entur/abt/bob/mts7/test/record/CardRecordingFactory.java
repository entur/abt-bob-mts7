package no.entur.abt.bob.mts7.test.record;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

public class CardRecordingFactory {

	public CardRecording newInstance() {
		return new CardRecording();
	}

	public CardRecording read(String resource) throws Exception {
		InputStream resourceAsStream = CardRecording.class.getResourceAsStream(resource);
		if (resourceAsStream == null) {
			throw new IllegalStateException(resource + " not found");
		}
		return read(resourceAsStream);
	}

	public CardRecording read(Path path) throws Exception {
		return read(Files.newInputStream(path));
	}

	public CardRecording read(File file) throws Exception {
		return read(new FileInputStream(file));
	}

	public CardRecording read(InputStream in) throws IOException {
		try {
			ObjectMapper objectMapper = getObjectMapper();
			ObjectReader reader = objectMapper.readerFor(CardRecording.class);

			return reader.readValue(in);
		} finally {
			in.close();
		}
	}

	protected ObjectMapper getObjectMapper() {
		SimpleModule module = new SimpleModule();
		module.addSerializer(CardInvocation.class, new CardInvocationSerializer());
		module.addDeserializer(CardInvocation.class, new CardInvocationDeserializer());

		return JsonMapper.builder().addModule(module).findAndAddModules().build();
	}

	public void write(byte[] randomValue, LocalDateTime dateTime, CardInvocationRecorderCard card, File file) throws Exception {
		write(randomValue, dateTime, card.getInvocations(), file);
	}

	public void write(byte[] randomValue, LocalDateTime dateTime, List<CardInvocation> invocations, File file) throws Exception {
		CardRecording cardRecording = new CardRecording();
		cardRecording.setInvocations(invocations);
		cardRecording.setRandomValue(randomValue);
		cardRecording.setTimestamp(Instant.now());

		if (dateTime != null) {
			cardRecording.setDateTime(dateTime);
		}
		write(cardRecording, file);
	}

	public void write(CardRecording value, String path) throws IOException {
		write(value, new FileOutputStream(path));
	}

	public void write(CardRecording value, File file) throws IOException {
		write(value, new FileOutputStream(file));
	}

	public void write(CardRecording value, OutputStream out) throws IOException {
		try {
			ObjectMapper mapper = getObjectMapper();
			ObjectWriter writer = mapper.writerFor(CardRecording.class).withDefaultPrettyPrinter();

			writer.writeValue(out, value);
		} finally {
			out.close();
		}
	}

	public void write(CardRecording value, Path path) throws IOException {
		OutputStream out = Files.newOutputStream(path);
		write(value, out);
	}

}
