package no.entur.abt.bob.mts7.test.record.bob;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.test.record.CardInvocation;
import no.entur.abt.bob.mts7.test.record.TransceiveInvocation;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class Mts7CardRecordingAnalyzerTest {

	private static final String SELECT = "00A4040006A00000078101";
	private static final String GET_DATA = "00CA7F21000000";
	private static final String GET_NEXT_DATA = "00CC7F21000000";
	private static final String GET_RESPONSE = "00C00000000000";
	private static final String INTERNAL_AUTHENTICATE = "0088000020" + "0000000000000000000000000000000000000000000000000000000000000000" + "00";

	private static class Events implements Mts7CardRecordingAnalyzer.Listener {

		private final List<String> events = new ArrayList<>();

		@Override
		public void onSelectApplicationCommand(byte[] commandApdu) throws IOException {
			events.add("select command");
		}

		@Override
		public void onSelectApplicationResponse(byte[] responseApdu) throws IOException {
			events.add("select response");
		}

		@Override
		public void onGetNextDataCommand(byte[] commandApdu) throws IOException {
			events.add("get data command");
		}

		@Override
		public void onGetNextDataResponse(byte[] responseApdu) throws IOException {
			events.add("get data response");
		}

		@Override
		public void onInternalAuthenticateCommand(byte[] commandApdu) throws IOException {
			events.add("authenticate command");
		}

		@Override
		public void onInternalAuthenticateResponse(byte[] responseApdu) throws IOException {
			events.add("authenticate response");
		}
	}

	private static CardInvocation invocation(String command, String response) {
		TransceiveInvocation invocation = new TransceiveInvocation();
		invocation.setCommand(ByteArrayHexStringConverter.hexStringToByteArray(command));
		invocation.setResponse(ByteArrayHexStringConverter.hexStringToByteArray(response));
		return invocation;
	}

	@Test
	public void testGetResponseIsAKnownCommand() {
		Mts7CardCommandType type = Mts7CardCommandType.parseCommandApdu(ByteArrayHexStringConverter.hexStringToByteArray(GET_RESPONSE));

		assertNotNull(type);
		assertEquals("Get response", type.getName());
	}

	@Test
	public void testTruncatedGetResponseCommandIsUnknown() {
		assertNull(Mts7CardCommandType.parseCommandApdu(ByteArrayHexStringConverter.hexStringToByteArray("00C0")));
	}

	@Test
	public void testResponseToGetResponseCommand() throws Exception {
		Events events = new Events();

		new Mts7CardRecordingAnalyzer(events).process(java.util.Arrays.asList(invocation(SELECT, "6F009000"), invocation(GET_NEXT_DATA, "0102036100"),
				invocation(GET_RESPONSE, "0405069000"), invocation(INTERNAL_AUTHENTICATE, "0102039000")));

		// get response is part of the response to get next data, and has no event of its own
		assertEquals(java.util.Arrays.asList("select command", "select response", "get data command", "get data response", "authenticate command",
				"authenticate response"), events.events);
	}

	@Test
	public void testResponseToGetDataCommand() throws Exception {
		Events events = new Events();

		new Mts7CardRecordingAnalyzer(events).process(java.util.Arrays.asList(invocation(GET_DATA, "0102039000")));

		assertEquals(java.util.Arrays.asList("get data command", "get data response"), events.events);
	}

	@Test
	public void testUnknownCommand() {
		Mts7CardRecordingAnalyzer analyzer = new Mts7CardRecordingAnalyzer(new Events());

		assertThrows(IllegalStateException.class, () -> analyzer.processCommand(ByteArrayHexStringConverter.hexStringToByteArray("00B0000000")));
	}

}
