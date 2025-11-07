package no.entur.abt.bob.mts7.core.pki;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;

import no.entur.abt.bob.api.pm.model.JwkPublic;
import no.entur.abt.bob.api.pm.model.ParticipantMetadata;

public class ParticipantPublicKeysTest {

	@Test
	public void parseRootCertififcates() throws Exception {
		ObjectMapper mapper = new ObjectMapper();

		InputStream is = getClass().getResourceAsStream("/participantMetadata.json");

		List<ParticipantMetadata> participantMetadata = Arrays.asList(mapper.readValue(is, ParticipantMetadata[].class));
		assertFalse(participantMetadata.isEmpty());

		ParticipantPublicKeys participantPublicKeys = ParticipantPublicKeys.newBuilder().withParticipants(participantMetadata).build();

		for (ParticipantMetadata p : participantMetadata) {
			List<JwkPublic> mtbPublicKeys = p.getMtbPublicKeys();

			for (JwkPublic key : mtbPublicKeys) {
				IssuerPublicKey issuerPublicKey = participantPublicKeys.getIssuerPublicKey(p.getPid(), key.getKid());

				assertNotNull(issuerPublicKey);
			}
		}

	}

}
