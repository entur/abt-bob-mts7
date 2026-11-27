package no.entur.abt.bob.mts7.core;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;

public class UnknownIssuerKeyPolicyTest {

	private static final Instant NOW = Instant.parse("2026-11-27T12:00:00Z");
	private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

	@Test
	public void testBlameCardOrKeys() throws Exception {
		assertTrue(UnknownIssuerKeyPolicy.blameCard().isCardToBlame(10, "10:1", keys()));
		assertFalse(UnknownIssuerKeyPolicy.blameKeys().isCardToBlame(10, "10:1", keys()));
	}

	@Test
	public void testBlameCardIfConfirmedWithin() throws Exception {
		Duration day = Duration.ofDays(1);

		// confirmed recently, so the keys are up to date and the card is to blame
		assertTrue(UnknownIssuerKeyPolicy.blameCardIfConfirmedWithin(day, () -> NOW.minus(Duration.ofHours(1)), CLOCK).isCardToBlame(10, "10:1", keys()));
		assertTrue(UnknownIssuerKeyPolicy.blameCardIfConfirmedWithin(day, () -> NOW.minus(day), CLOCK).isCardToBlame(10, "10:1", keys()));

		// not confirmed for too long, or never, so the keys may be out of date
		assertFalse(UnknownIssuerKeyPolicy.blameCardIfConfirmedWithin(day, () -> NOW.minus(day).minusSeconds(1), CLOCK).isCardToBlame(10, "10:1", keys()));
		assertFalse(UnknownIssuerKeyPolicy.blameCardIfConfirmedWithin(day, () -> null, CLOCK).isCardToBlame(10, "10:1", keys()));

		assertThrows(IllegalArgumentException.class, () -> UnknownIssuerKeyPolicy.blameCardIfConfirmedWithin(Duration.ofSeconds(-1), () -> NOW, CLOCK));
	}

	@Test
	public void testAnd() throws Exception {
		UnknownIssuerKeyPolicy card = UnknownIssuerKeyPolicy.blameCard();
		UnknownIssuerKeyPolicy keys = UnknownIssuerKeyPolicy.blameKeys();

		assertTrue(card.and(card).isCardToBlame(10, "10:1", keys()));
		assertFalse(card.and(keys).isCardToBlame(10, "10:1", keys()));
		assertFalse(keys.and(card).isCardToBlame(10, "10:1", keys()));
	}

	private static ParticipantPublicKeys keys() throws Exception {
		return ParticipantPublicKeys.newBuilder().build();
	}

}
