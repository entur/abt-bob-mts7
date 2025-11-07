package no.entur.abt.bob.mts7.core.pki;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.InputStream;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

public class IccSignatureFactoryTest {

	private ObjectMapper objectMapper = new ObjectMapper();

	@Test
	public void testParse() throws Exception {
		IccPublicKeyFactory factory = new IccPublicKeyFactory();

		InputStream in = getClass().getResourceAsStream("/card.json");

		Map fields = objectMapper.readValue(in, Map.class);

		List<Map<String, Object>> list = (List<Map<String, Object>>) fields.get("p");

		IccPublicKey create = factory.create(list.get(0));
		assertNotNull(create);
	}
}
