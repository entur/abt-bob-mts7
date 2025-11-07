package no.entur.abt.bob.mts7.simple.reader;

import java.io.IOException;

public interface Mts7Exchange {

	byte[] getTagId();

	byte[] transceive(byte[] data) throws IOException;

}
