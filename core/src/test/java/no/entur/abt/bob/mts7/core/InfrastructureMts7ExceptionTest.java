package no.entur.abt.bob.mts7.core;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class InfrastructureMts7ExceptionTest {

	@Test
	public void testCardSideIsNotOurSide() {
		for (Class<?> c : new Class<?>[] { UnableToConstructIccKeyException.class, IccKeyInvalidCardMts7Exception.class, KeyPairInvalidCardMts7Exception.class,
				TrustChainInvalidCardMts7Exception.class, UnknownIssuerKeyInvalidCardMts7Exception.class }) {
			assertTrue(InvalidCardMts7Exception.class.isAssignableFrom(c), c.getName());
			assertFalse(InfrastructureMts7Exception.class.isAssignableFrom(c), c.getName());
		}
	}

	@Test
	public void testCardSideFromTheHelpersHasAnEmptyCard() {
		// thrown where the card is not known, but never without a card
		assertNotNull(new UnableToConstructIccKeyException("Missing token public key").getResult());
		assertNotNull(new UnableToConstructIccKeyException(new IllegalArgumentException()).getResult());
	}

	@Test
	public void testOurSideIsNotCardSide() {
		for (Class<?> c : new Class<?>[] { UnableToConstructIssuerKeyException.class, NoSuchAlgorithmMts7Exception.class,
				UnableToConstructThumbprintKeyException.class }) {
			assertTrue(InfrastructureMts7Exception.class.isAssignableFrom(c), c.getName());
			assertFalse(InvalidCardMts7Exception.class.isAssignableFrom(c), c.getName());
		}
		assertFalse(InfrastructureMts7Exception.class.isAssignableFrom(InvalidCardMts7Exception.class));
	}

}
