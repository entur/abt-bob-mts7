package no.entur.abt.bob.mts7.reader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.api.UnableToSelectApplicationException;
import no.entur.abt.bob.mts7.api.apdu.CommandAPDU;
import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.core.Mts7CardEnricher;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;
import no.entur.abt.bob.mts7.core.UnableToVerifyKeyPairException;
import no.entur.abt.bob.mts7.reader.processor.Mts7Processor;
import no.entur.abt.bob.mts7.reader.processor.Mts7ProcessorFactory;
import no.entur.abt.bob.mts7.reader.processor.VerifyKeyPairMts7Processor;
import no.entur.abt.bob.mts7.reader.processor.VerifyKeyPairMts7ProcessorFactory;
import no.entur.abt.bob.mts7.reader.processor.VerifyTrustChainMts7Processor;
import no.entur.abt.bob.mts7.reader.processor.VerifyTrustChainMts7ProcessorFactory;
import no.entur.abt.bob.mts7.test.util.ConcurrentRunner;
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

	private static final byte[] GET_NEXT_DATA_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000");
	private static final byte[] SIGNATURE_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");

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
		return Arrays.asList(new VerifyKeyPairMts7ProcessorFactory(executor), new VerifyTrustChainMts7ProcessorFactory(participantPublicKeys, executor));
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
		// use the same snapshot for the decision and the assertion; a thread which has been started but is not yet running might otherwise show up between the
		// two
		Set<Thread> threads = newProcessorThreads();
		while (!threads.isEmpty() && System.currentTimeMillis() < deadline) {
			Thread.sleep(10);
			threads = newProcessorThreads();
		}
		assertTrue(threads.isEmpty(), message + ": processor thread is still running");
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
	public void testStartTwiceStartsOneThread() throws Exception {
		for (Mts7ProcessorFactory processorFactory : processorFactories()) {
			Mts7Processor processor = processorFactory.create();
			processor.start();
			processor.start();
			try {
				// give a second thread the chance to start
				Thread.sleep(200);

				assertEquals(1, newProcessorThreads().size(), processorFactory.getClass().getSimpleName() + ": number of processor threads");
			} finally {
				processor.close();
			}
			assertNoProcessorThreadsLeft(processorFactory.getClass().getSimpleName());
		}
	}

	@Test
	public void testCloseBeforeStartDoesNotStart() throws Exception {
		for (Mts7ProcessorFactory processorFactory : processorFactories()) {
			String name = processorFactory.getClass().getSimpleName();

			Mts7Processor processor = processorFactory.create();
			processor.close();
			processor.start();

			// would wait forever for input if it had been started
			assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
				UnableToVerifyKeyPairException e = assertThrows(UnableToVerifyKeyPairException.class, () -> processor.waitForVerify(0));
				assertNotNull(e.getResult());
			}, name);

			assertNoProcessorThreadsLeft(name);
		}
	}

	@Test
	public void testCloseIsIdempotent() throws Exception {
		for (Mts7ProcessorFactory processorFactory : processorFactories()) {
			Mts7Processor processor = processorFactory.create();
			processor.start();

			processor.close();
			processor.close();

			assertNoProcessorThreadsLeft(processorFactory.getClass().getSimpleName());
		}
	}

	@Test
	public void testCloseFromSeveralThreads() throws Exception {
		for (Mts7ProcessorFactory processorFactory : processorFactories()) {
			String name = processorFactory.getClass().getSimpleName();

			for (int i = 0; i < 20; i++) {
				Mts7Processor processor = processorFactory.create();
				processor.start();

				List<Throwable> failures = ConcurrentRunner.run(4, 1, (thread, iteration) -> processor.close());

				assertTrue(failures.isEmpty(), name + ": " + failures);
			}
			assertNoProcessorThreadsLeft(name);
		}
	}

	@Test
	public void testCardAfterTimeoutIsNotChangedByTheProcessor() throws Exception {
		for (Mts7ProcessorFactory processorFactory : processorFactories()) {
			String name = processorFactory.getClass().getSimpleName();

			Mts7Processor processor = processorFactory.create();
			processor.start();

			processor.onSelectApplicationResponseApdu(SELECT_APPLICATION_RESPONSE);

			// still waiting for the rest
			UnableToVerifyKeyPairException e = assertThrows(UnableToVerifyKeyPairException.class, () -> processor.waitForVerify(300));

			Mts7Card timedOut = e.getResult();
			assertNotNull(timedOut);
			assertFalse(timedOut.isVerifiedPrivateKeyPresent(), name);

			// the card gets complete
			processor.onGetDataResponseApdu(GET_NEXT_DATA_RESPONSE);

			byte[] challenge = new byte[32];
			processor.onInternalAuthenticateApdu(new CommandAPDU(0, 0, 0, 0, challenge).getBytes(), SIGNATURE_RESPONSE);

			Mts7Card complete = processor.waitForVerify(0);
			assertTrue(complete.isVerifiedPrivateKeyPresent(), name);

			// the earlier card is a snapshot, so it is not changed by what happened after it was handed out
			assertFalse(timedOut.isVerifiedPrivateKeyPresent(), name + ": card was changed after waitForVerify returned");
			assertEquals("0000175F96B61D", ByteArrayHexStringConverter.toHexString(timedOut.getSerial()), name);

			processor.close();
			assertNoProcessorThreadsLeft(name);
		}
	}

	/**
	 * Processors which give up after a short while.
	 */

	private List<Mts7Processor> impatientProcessors() throws Exception {
		IccPublicKeyFactory iccPublicKeyFactory = new IccPublicKeyFactory();
		Mts7CardEnricher enricher = new Mts7CardEnricher();
		CBORMapper cborMapper = new CBORMapper();
		ThumbprintFactory thumbprintFactory = new ThumbprintFactory(null);

		return Arrays.<Mts7Processor>asList(new VerifyKeyPairMts7Processor(iccPublicKeyFactory, enricher, cborMapper, thumbprintFactory, executor) {
			@Override
			protected long getMaxLifetimeMillis() {
				return 300;
			}
		}, new VerifyTrustChainMts7Processor(participantPublicKeys, iccPublicKeyFactory, enricher, cborMapper, thumbprintFactory, executor) {
			@Override
			protected long getMaxLifetimeMillis() {
				return 300;
			}
		});
	}

	@Test
	public void testProcessorGivesUpWhenTheCardIsNotRead() throws Exception {
		for (Mts7Processor processor : impatientProcessors()) {
			String name = processor.getClass().getSuperclass().getSimpleName();

			processor.start();

			// nobody closes it, and there is no input, but it must not wait forever
			assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
				UnableToVerifyKeyPairException e = assertThrows(UnableToVerifyKeyPairException.class, () -> processor.waitForVerify(0));
				assertNotNull(e.getResult());
			}, name);

			assertNoProcessorThreadsLeft(name);
		}
	}

}
