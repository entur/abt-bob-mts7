package no.entur.abt.bob.mts7.test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import no.entur.abt.bob.mts7.utils.nfc.Card;

public class ListResponseCard implements Card {

	private List<byte[]> commands = new ArrayList<>();
	private int offset = 0;

	@Override
	public byte[] transceive(byte[] data) throws IOException {
		try {
			return commands.get(offset);
		} finally {
			offset++;
		}
	}

	public void add(byte[] command) {
		this.commands.add(command);
	}

}
