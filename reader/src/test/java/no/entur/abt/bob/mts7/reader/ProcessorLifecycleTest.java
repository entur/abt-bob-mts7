package no.entur.abt.bob.mts7.reader;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.api.UnableToSelectApplicationException;
import no.entur.abt.bob.mts7.core.UnableToVerifyKeyPairException;
import no.entur.abt.bob.mts7.reader.processor.Mts7Processor;
import no.entur.abt.bob.mts7.reader.processor.Mts7ProcessorFactory;
import no.entur.abt.bob.mts7.reader.processor.VerifyKeyPairMts7ProcessorFactory;
import no.entur.abt.bob.mts7.reader.processor.VerifyTrustChainMts7ProcessorFactory;
import no.entur.abt.bob.mts7.test.util.MockRandomFactory;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;
import no.entur.abt.bob.mts7.utils.nfc.Card;

/**
 * Tests that the processor threads are not left behind (waiting forever for input which will never arrive), and that the processors fail with the declared
 * exceptions when no input arrived.
 */

public class ProcessorLifecycleTest extends AbstractTest {

	private static final String PROCESSOR_PACKAGE = "no.entur.abt.bob.mts7.reader.processor.";

	private static final byte[] SELECT_APPLICATION_RESPONSE = ByteArrayHexStringConverter
			.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");

	private Set<Thread> threadsBefore;

	@BeforeEach
	public void rememberThreads() {
		threadsBefore = processorThreads();
	}

	@AfterEach
	public void stopLeakedThreads() {
		// do not let a failing test leave threads behind
		for (Thread thread : newProcessorThreads()) {
			thread.interrupt();
		}
	}

	private List<Mts7ProcessorFactory> processorFactories() throws Exception {
		return Arrays.asList(new VerifyKeyPairMts7ProcessorFactory(), new VerifyTrustChainMts7ProcessorFactory(participantPublicKeys));
	}

	/**
	 * Threads currently running one of the processors.
	 */

	private static Set<Thread> processorThreads() {
		Set<Thread> result = new HashSet<>();
		for (Map.Entry<Thread, StackTraceElement[]> entry : Thread.getAllStackTraces().entrySet()) {
			for (StackTraceElement element : entry.getValue()) {
				if (element.getClassName().startsWith(PROCESSOR_PACKAGE) && element.getMethodName().equals("run")) {
					result.add(entry.getKey());
					break;
				}
			}
		}
		return result;
	}

	private Set<Thread> newProcessorThreads() {
		Set<Thread> result = processorThreads();
		result.removeAll(threadsBefore);
		return result;
	}

	private void assertNoProcessorThreadsLeft(String message) throws InterruptedException {
		long deadline = System.currentTimeMillis() + 2000;
		while (!newProcessorThreads().isEmpty() && System.currentTimeMillis() < deadline) {
			Thread.sleep(10);
		}
		assertTrue(newProcessorThreads().isEmpty(), message + ": processor thread is still running");
	}

	private Thread awaitProcessorThread() throws InterruptedException {
		long deadline = System.currentTimeMillis() + 2000;
		while (newProcessorThreads().isEmpty() && System.currentTimeMillis() < deadline) {
			Thread.sleep(10);
		}
		Set<Thread> threads = newProcessorThreads();
		assertTrue(threads.size() == 1, "Expected one processor thread, got " + threads.size());
		return threads.iterator().next();
	}

	private InFlightMts7CardFactory newFactory(Mts7ProcessorFactory processorFactory) throws Exception {
		return new InFlightMts7CardFactory(processorFactory, MockRandomFactory.newInstance(new byte[32]));
	}

	@Test
	public void testProcessorStoppedWhenCardFailsDuringRead() throws Exception {
		for (Mts7ProcessorFactory processorFactory : processorFactories()) {
			String name = processorFactory.getClass().getSimpleName();

			InFlightMts7CardFactory factory = newFactory(processorFactory);

			Card card = mock(Card.class);
			when(card.transceive(any(byte[].class))).thenReturn(SELECT_APPLICATION_RESPONSE).thenThrow(new IOException("card gone"));

			assertThrows(IOException.class, () -> factory.create(new DefaultMts7Card(card), null));

			assertNoProcessorThreadsLeft(name);
		}
	}

	@Test
	public void testProcessorStoppedWhenSelectApplicationFails() throws Exception {
		for (Mts7ProcessorFactory processorFactory : processorFactories()) {
			String name = processorFactory.getClass().getSimpleName();

			InFlightMts7CardFactory factory = newFactory(processorFactory);

			Card card = mock(Card.class);
			when(card.transceive(any(byte[].class))).thenReturn(ByteArrayHexStringConverter.hexStringToByteArray("6A82"));

			assertThrows(UnableToSelectApplicationException.class, () -> factory.create(new DefaultMts7Card(card), null));

			assertNoProcessorThreadsLeft(name);
		}
	}

	@Test
	public void testCloseStopsProcessorAfterWaitForVerifyTimeout() throws Exception {
		for (Mts7ProcessorFactory processorFactory : processorFactories()) {
			String name = processorFactory.getClass().getSimpleName();

			Mts7Processor processor = processorFactory.create();
			processor.start();

			// no input, so this times out
			UnableToVerifyKeyPairException e = assertThrows(UnableToVerifyKeyPairException.class, () -> processor.waitForVerify(100));
			assertNotNull(e.getResult());

			// the processor must still be closable after the timeout
			processor.close();

			assertNoProcessorThreadsLeft(name);
		}
	}

	@Test
	public void testWaitForVerifyAfterCloseIsNotVerified() throws Exception {
		for (Mts7ProcessorFactory processorFactory : processorFactories()) {
			Mts7Processor processor = processorFactory.create();
			processor.start();
			processor.close();

			UnableToVerifyKeyPairException e = assertThrows(UnableToVerifyKeyPairException.class, () -> processor.waitForVerify(1000));
			assertNotNull(e.getResult());
		}
	}

	@Test
	public void testWaitForVerifyWithoutInputIsNotVerified() throws Exception {
		for (Mts7ProcessorFactory processorFactory : processorFactories()) {
			Mts7Processor processor = processorFactory.create();
			// never started
			UnableToVerifyKeyPairException e = assertThrows(UnableToVerifyKeyPairException.class, () -> processor.waitForVerify(1));
			assertNotNull(e.getResult());
		}
	}

	@Test
	public void testProcessorThreadDoesNotPreventJvmExit() throws Exception {
		for (Mts7ProcessorFactory processorFactory : processorFactories()) {
			Mts7Processor processor = processorFactory.create();
			processor.start();
			try {
				assertTrue(awaitProcessorThread().isDaemon(), processorFactory.getClass().getSimpleName() + ": processor thread should be a daemon thread");
			} finally {
				processor.close();
			}
			assertNoProcessorThreadsLeft(processorFactory.getClass().getSimpleName());
		}
	}

}
