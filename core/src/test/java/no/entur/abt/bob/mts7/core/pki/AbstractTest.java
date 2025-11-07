package no.entur.abt.bob.mts7.core.pki;

import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;

import com.fasterxml.jackson.databind.ObjectMapper;

import no.entur.abt.bob.api.pm.model.ParticipantMetadata;

public abstract class AbstractTest {

	protected ObjectMapper mapper = new ObjectMapper();

	protected ParticipantPublicKeys participantPublicKeys;

	protected IccPublicKeyFactory factory = new IccPublicKeyFactory();

	@BeforeEach
	public void setup() throws Exception {
		InputStream is = getClass().getResourceAsStream("/participantMetadata.json");

		List<ParticipantMetadata> participantMetadata = Arrays.asList(mapper.readValue(is, ParticipantMetadata[].class));
		assertFalse(participantMetadata.isEmpty());

		participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();
	}

}
