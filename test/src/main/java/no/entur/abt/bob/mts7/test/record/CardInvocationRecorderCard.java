package no.entur.abt.bob.mts7.test.record;

import java.io.Closeable;
import java.io.IOException;
import java.util.List;

import no.entur.abt.bob.mts7.utils.nfc.Card;

/**
 *
 * Helper class for transparent recording of tag interactions.
 *
 */

public class CardInvocationRecorderCard implements Card, Closeable {

	private final Card delegate;
	private final CardInvocationRecorder listener = new CardInvocationRecorder();

	public CardInvocationRecorderCard(Card delegate) {
		this.delegate = delegate;
	}

	@Override
	public byte[] transceive(byte[] data) throws IOException {
		TransceiveInvocation invocation = listener.onTransceive(data);
		try {
			byte[] transceive = delegate.transceive(data);
			invocation.setResponse(transceive);
			return transceive;
		} catch (Exception e) {
			invocation.setException(e);
			throw e;
		} finally {
			invocation.completed(System.nanoTime());
		}
	}

	@Override
	public void close() throws IOException {
		CloseInvocation invocation = listener.onClose();
		try {
			if (delegate instanceof Closeable) {
				Closeable closeable = (Closeable) delegate;
				closeable.close();
			}
		} catch (Exception e) {
			invocation.setException(e);
			throw e;
		} finally {
			invocation.completed(System.nanoTime());
		}
	}

	public List<CardInvocation> getInvocations() {
		return listener.getInvocations();
	}

}
