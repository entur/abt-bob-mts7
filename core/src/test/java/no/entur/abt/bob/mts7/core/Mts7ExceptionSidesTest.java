package no.entur.abt.bob.mts7.core;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.api.InsufficientCardCommandsException;
import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.api.MalformedCardResponseException;
import no.entur.abt.bob.mts7.api.ReaderMts7Exception;
import no.entur.abt.bob.mts7.api.UnableToSelectApplicationException;
import no.entur.abt.bob.mts7.api.UnexpectedCardResponseException;
import no.entur.abt.bob.mts7.api.VerifierMts7Exception;

/**
 * Each exception is a problem of exactly one side: the card, the reader, or us.
 */

public class Mts7ExceptionSidesTest {

	private static final Class<?>[] SIDES = { InvalidCardMts7Exception.class, ReaderMts7Exception.class, VerifierMts7Exception.class };

	private static void assertSide(Class<?> expected, Class<?>... exceptions) {
		for (Class<?> c : exceptions) {
			List<Class<?>> sides = new ArrayList<>();
			for (Class<?> side : SIDES) {
				if (side.isAssignableFrom(c)) {
					sides.add(side);
				}
			}
			assertEquals(List.of(expected), sides, c.getName());
		}
	}

	@Test
	public void testCardSide() {
		assertSide(InvalidCardMts7Exception.class, NonCompliantIccKeyInvalidCardMts7Exception.class, KeyPairInvalidCardMts7Exception.class,
				TrustChainInvalidCardMts7Exception.class, UnknownIssuerKeyInvalidCardMts7Exception.class, UnexpectedCardResponseException.class,
				UnableToSelectApplicationException.class);
	}

	@Test
	public void testReaderSide() {
		assertSide(ReaderMts7Exception.class, MissingCardCommandsException.class, InsufficientCardCommandsException.class, UnexpectedCardCommandException.class,
				MalformedCardCommandException.class, MalformedCardResponseException.class);
	}

	@Test
	public void testOurSide() {
		assertSide(VerifierMts7Exception.class, UnableToConstructIssuerKeyException.class, NoSuchAlgorithmMts7Exception.class,
				UnableToConstructThumbprintKeyException.class, UnableToConstructIccKeyException.class, OutdatedIssuerKeysException.class);
	}

}
