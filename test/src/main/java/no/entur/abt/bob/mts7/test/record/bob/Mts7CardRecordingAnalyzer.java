package no.entur.abt.bob.mts7.test.record.bob;

import java.io.IOException;
import java.util.List;

import no.entur.abt.bob.mts7.test.record.AbstractCardRecordingAnalyzer;
import no.entur.abt.bob.mts7.test.record.CardInvocation;
import no.entur.abt.bob.mts7.test.record.TransceiveInvocation;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class Mts7CardRecordingAnalyzer extends AbstractCardRecordingAnalyzer {

	public interface Listener {

		void onSelectApplicationCommand(byte[] commandApdu) throws IOException;

		void onSelectApplicationResponse(byte[] responseApdu) throws IOException;

		void onGetNextDataCommand(byte[] commandApdu) throws IOException;

		void onGetNextDataResponse(byte[] responseApdu) throws IOException;

		void onInternalAuthenticateCommand(byte[] commandApdu) throws IOException;

		void onInternalAuthenticateResponse(byte[] responseApdu) throws IOException;

	}

	protected Listener listener;

	// the current (last) command
	protected Mts7CardCommandType command;

	public Mts7CardRecordingAnalyzer() {
		for (Mts7CardCommandType command : Mts7CardCommandType.values()) {
			addCommandIdentifier(command.getBytes(), command.getName());
		}
	}

	public Mts7CardRecordingAnalyzer(Listener listener) {
		this();
		this.listener = listener;
	}

	public void process(List<CardInvocation> invocations) throws IOException {

		for (CardInvocation cardInvocation : invocations) {
			if (cardInvocation instanceof TransceiveInvocation) {
				TransceiveInvocation transceive = (TransceiveInvocation) cardInvocation;

				processCommand(transceive.getCommand());
				processResponse(transceive.getResponse());
			}
		}
	}

	public Mts7CardCommandType processCommand(byte[] commandApdu) throws IOException {
		command = Mts7CardCommandType.parseCommandApdu(commandApdu);
		if (command != null) {

			switch (command) {
			case SELECT_APPLICATION: {
				listener.onSelectApplicationCommand(commandApdu);
				break;
			}
			case GET_DATA_COMMAND:
			case GET_NEXT_DATA_COMMAND: {
				listener.onGetNextDataCommand(commandApdu);
				break;
			}
			case INTERNAL_AUTHENTICATE: {
				listener.onInternalAuthenticateCommand(commandApdu);
				break;
			}
			default: {
				throw new IllegalStateException("Unknown command " + command);
			}
			}
			return command;
		} else {
			throw new IllegalStateException("Unknown command " + ByteArrayHexStringConverter.toHexString(commandApdu));
		}
	}

	public void processResponse(byte[] responseApdu) throws IOException {
		switch (command) {
		case SELECT_APPLICATION: {
			listener.onSelectApplicationResponse(responseApdu);
			break;
		}
		case GET_NEXT_DATA_COMMAND: {
			listener.onGetNextDataResponse(responseApdu);
			break;
		}
		case INTERNAL_AUTHENTICATE: {
			listener.onInternalAuthenticateResponse(responseApdu);
			break;
		}
		default: {
			throw new IllegalStateException("Unknown command " + command);
		}
		}
	}

}
