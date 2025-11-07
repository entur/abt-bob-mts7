package no.entur.abt.bob.mts7.reader;

import java.io.IOException;

import no.entur.abt.bob.mts7.simple.reader.Mts7Exchange;
import no.entur.abt.bob.mts7.utils.nfc.Card;

public class DefaultMts7Card implements Mts7Exchange {

	private final Card card;

	public DefaultMts7Card(Card card) {
		this.card = card;
	}

	@Override
	public byte[] getTagId() {
		return null;
	}

	@Override
	public byte[] transceive(byte[] data) throws IOException {
		return card.transceive(data);
	}

}
