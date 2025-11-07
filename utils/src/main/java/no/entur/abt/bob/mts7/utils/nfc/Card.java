package no.entur.abt.bob.mts7.utils.nfc;

import java.io.IOException;

public interface Card {

	public byte[] transceive(byte[] data) throws IOException;

}
