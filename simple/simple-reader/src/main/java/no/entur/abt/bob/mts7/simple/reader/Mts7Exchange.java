package no.entur.abt.bob.mts7.simple.reader;

import java.io.IOException;

public interface Mts7Exchange {

	byte[] getTagId();

	/**
	 * Send a command to the card.
	 *
	 * @param data the command
	 * @return the response as the card sent it, with the status word; a response which is shorter than that is blamed on the card
	 * @throws IOException if the card cannot be reached
	 */

	byte[] transceive(byte[] data) throws IOException;

}
