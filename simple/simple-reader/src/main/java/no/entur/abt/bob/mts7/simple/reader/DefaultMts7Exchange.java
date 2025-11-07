package no.entur.abt.bob.mts7.simple.reader;

import java.io.IOException;

import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchanges;

public class DefaultMts7Exchange extends Mts7ApduExchanges implements Mts7Exchange {

	protected final Mts7Exchange delegate;

	public DefaultMts7Exchange(Mts7Exchange delegate) {
		this.delegate = delegate;
	}

	@Override
	public byte[] getTagId() {
		return delegate.getTagId();
	}

	@Override
	public byte[] transceive(byte[] command) throws IOException {

		byte[] response = delegate.transceive(command);

		add(command, response);

		return response;
	}

}
