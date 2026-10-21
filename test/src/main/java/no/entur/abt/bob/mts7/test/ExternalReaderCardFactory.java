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

	@SuppressWarnings("restriction")
	public CardTerminal createCardReader(long timeout) throws CardException {
		TerminalFactory factory = TerminalFactory.getDefault();

		CardTerminals cardTerminals = factory.terminals();

		List<CardTerminal> list = cardTerminals.list();
		if (list.isEmpty()) {
			long deadline = System.currentTimeMillis() + timeout;

			while (true) {
				list = cardTerminals.list();
				if (!list.isEmpty()) {
					break;
				}
				if (System.currentTimeMillis() > deadline) {
					throw new CardException("No card terminals available after timeout of " + timeout + "ms");
				}
				Thread.yield();
			}
		}
		for (CardTerminal terminal : list) {
			configureTerminal(terminal);
		}
		List<CardTerminal> terminals = list;

		list = cardTerminals.list(CardTerminals.State.CARD_PRESENT);

		if (list.isEmpty()) {
			cardTerminals.waitForChange(timeout);
			list = cardTerminals.list(CardTerminals.State.CARD_PRESENT);
		}

		if (list.isEmpty()) {
			StringBuilder names = new StringBuilder();
			for (CardTerminal terminal : terminals) {
				if (names.length() > 0) {
					names.append(", ");
				}
				names.append(terminal.getName());
			}
			throw new CardException("No card present in any card terminal after timeout of " + timeout + "ms (terminals: " + names + ")");
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
