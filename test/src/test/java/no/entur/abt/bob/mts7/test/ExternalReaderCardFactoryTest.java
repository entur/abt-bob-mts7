package no.entur.abt.bob.mts7.test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;

import org.junit.jupiter.api.Test;

public class ExternalReaderCardFactoryTest {

	private static class Terminal extends CardTerminal {

		private final boolean cardPresent;

		public Terminal(boolean cardPresent) {
			this.cardPresent = cardPresent;
		}

		@Override
		public String getName() {
			return "test";
		}

		@Override
		public Card connect(String protocol) throws CardException {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean isCardPresent() throws CardException {
			return cardPresent;
		}

		@Override
		public boolean waitForCardPresent(long timeout) throws CardException {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean waitForCardAbsent(long timeout) throws CardException {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * Terminals where the terminal shows up after a delay (or never).
	 */

	private static class DelayedTerminals extends CardTerminals {

		private final long appearsAfter;
		private final long start = System.currentTimeMillis();
		private final CardTerminal terminal;

		private final AtomicInteger listCalls = new AtomicInteger();

		public DelayedTerminals(long appearsAfter, CardTerminal terminal) {
			this.appearsAfter = appearsAfter;
			this.terminal = terminal;
		}

		@Override
		public List<CardTerminal> list(State state) throws CardException {
			listCalls.incrementAndGet();

			if (System.currentTimeMillis() - start < appearsAfter) {
				return Collections.emptyList();
			}
			return Arrays.asList(terminal);
		}

		@Override
		public boolean waitForChange(long timeout) throws CardException {
			return false;
		}

		public int getListCalls() {
			return listCalls.get();
		}
	}

	private final ExternalReaderCardFactory factory = new ExternalReaderCardFactory();

	@Test
	public void testTerminalPresent() throws Exception {
		CardTerminal terminal = new Terminal(true);
		DelayedTerminals terminals = new DelayedTerminals(0, terminal);

		assertSame(terminal, factory.createCardReader(terminals, 1000));
	}

	@Test
	public void testWaitForTerminalWithoutBusyWaiting() throws Exception {
		CardTerminal terminal = new Terminal(true);
		DelayedTerminals terminals = new DelayedTerminals(300, terminal);

		long start = System.currentTimeMillis();
		assertSame(terminal, factory.createCardReader(terminals, 5000));
		long elapsed = System.currentTimeMillis() - start;

		assertTrue(elapsed >= 250, "Returned after " + elapsed + "ms");
		// polling a few times a second, not as fast as possible (which is thousands of times)
		assertTrue(terminals.getListCalls() < 100, "list() was called " + terminals.getListCalls() + " times");
	}

	@Test
	public void testTimeoutWaitingForTerminal() throws Exception {
		DelayedTerminals terminals = new DelayedTerminals(Long.MAX_VALUE, new Terminal(true));

		long start = System.currentTimeMillis();
		CardException e = assertThrows(CardException.class, () -> factory.createCardReader(terminals, 300));
		long elapsed = System.currentTimeMillis() - start;

		assertTrue(e.getMessage().contains("300ms"), e.getMessage());
		assertTrue(elapsed >= 300 && elapsed < 3000, "Gave up after " + elapsed + "ms");
		assertTrue(terminals.getListCalls() < 100, "list() was called " + terminals.getListCalls() + " times");
	}

	@Test
	public void testInterruptedWaitingForTerminal() throws Exception {
		DelayedTerminals terminals = new DelayedTerminals(Long.MAX_VALUE, new Terminal(true));

		AtomicReference<Throwable> thrown = new AtomicReference<>();
		AtomicReference<Boolean> interrupted = new AtomicReference<>();

		Thread thread = new Thread(() -> {
			try {
				factory.createCardReader(terminals, 60_000);
			} catch (Throwable e) {
				thrown.set(e);
			}
			interrupted.set(Thread.currentThread().isInterrupted());
		});
		thread.start();

		Thread.sleep(100);
		thread.interrupt();
		thread.join(5000);

		assertEquals(false, thread.isAlive(), "Still waiting after interrupt");
		assertTrue(thrown.get() instanceof CardException, String.valueOf(thrown.get()));
		assertEquals(Boolean.TRUE, interrupted.get(), "The thread must still be interrupted");
	}

}
