package no.entur.abt.bob.mts7.test;

import java.util.List;

import javax.smartcardio.ATR;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.TerminalFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class ExternalReaderCardFactory {

	private static final Logger LOGGER = LoggerFactory.getLogger(ExternalReaderCardFactory.class);

	// milliseconds between looking for card terminals
	private static final long TERMINAL_POLL_INTERVAL = 50;

	@SuppressWarnings("restriction")
	public CardTerminal createCardReader(long timeout) throws CardException {
		TerminalFactory factory = TerminalFactory.getDefault();

		return createCardReader(factory.terminals(), timeout);
	}

	public CardTerminal createCardReader(CardTerminals cardTerminals, long timeout) throws CardException {
		List<CardTerminal> list = cardTerminals.list();
		if (list.isEmpty()) {
			long deadline = System.currentTimeMillis() + timeout;

			while (true) {
				list = cardTerminals.list();
				if (!list.isEmpty()) {
					break;
				}
				long remaining = deadline - System.currentTimeMillis();
				if (remaining <= 0) {
					throw new CardException("No card terminals available after timeout of " + timeout + "ms");
				}
				try {
					// do not use all the CPU while waiting for a reader to be connected
					Thread.sleep(Math.min(TERMINAL_POLL_INTERVAL, remaining));
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();

					throw new CardException("Interrupted while waiting for card terminals", e);
				}
			}
		}
		for (CardTerminal terminal : list) {
			configureTerminal(terminal);
		}
		list = cardTerminals.list(CardTerminals.State.CARD_PRESENT);

		if (list.isEmpty()) {
			cardTerminals.waitForChange(timeout);
			list = cardTerminals.list(CardTerminals.State.CARD_PRESENT);
		}

		if (list.isEmpty()) {
			throw new CardException("No card terminals available");
		}
		return list.get(0);
	}

	private void configureTerminal(CardTerminal terminal) throws CardException {
		// NOOP
	}

	@SuppressWarnings("restriction")
	public ExternalReaderCard createCard(long timeout) throws CardException {
		CardTerminal cardTerminal = createCardReader(timeout);

		// Connect with the card
		Card card = cardTerminal.connect("*");

		ATR atr = card.getATR();

		System.out.println(ByteArrayHexStringConverter.toHexString(atr.getBytes()));
		System.out.println(ByteArrayHexStringConverter.toHexString(atr.getHistoricalBytes()));

		return new ExternalReaderCard(card.getBasicChannel(), card);
	}

}
