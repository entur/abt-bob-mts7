package no.entur.abt.bob.mts7.test;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class ExternalReaderCard implements no.entur.abt.bob.mts7.utils.nfc.Card, Closeable {

	private final static Logger LOGGER = LoggerFactory.getLogger(ExternalReaderCard.class);

	private final Card card;
	private final CardChannel cardChannel;

	public ExternalReaderCard(CardChannel cardChannel, Card card) {
		this.card = card;
		this.cardChannel = cardChannel;
	}

	@Override
	public byte[] transceive(byte[] command) throws IOException {

		ByteBuffer outputBuffer = ByteBuffer.allocate(1024);

		try {
			int count = cardChannel.transmit(ByteBuffer.wrap(command), outputBuffer);

			byte[] response = new byte[count];
			System.arraycopy(outputBuffer.array(), 0, response, 0, response.length);

			return response;
		} catch (CardException e) {
			throw new IOException(e);
		}
	}

	@Override
	public void close() throws IOException {
		try {
			card.disconnect(false);
		} catch (CardException e) {
			throw new IOException(e);
		}
	}

	@Override
	public String toString() {
		return "ExternalReaderCard [" + ByteArrayHexStringConverter.toHexString(card.getATR().getBytes()) + "]";
	}

}
