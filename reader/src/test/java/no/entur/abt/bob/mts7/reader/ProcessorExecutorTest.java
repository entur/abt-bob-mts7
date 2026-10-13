package no.entur.abt.bob.mts7.reader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Provider;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.core.UnableToVerifyKeyPairException;
import no.entur.abt.bob.mts7.reader.processor.Mts7Processor;
import no.entur.abt.bob.mts7.reader.processor.VerifyKeyPairMts7ProcessorFactory;
import no.entur.abt.bob.mts7.reader.processor.VerifyTrustChainMts7ProcessorFactory;
import no.entur.abt.bob.mts7.test.ListResponseCard;
import no.entur.abt.bob.mts7.test.util.ConcurrentRunner;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * Test running the processors on an executor provided by the application, i.e. threads which are reused for the next card.
 */

public class ProcessorExecutorTest extends AbstractTest {

	private static final byte[] SELECT_APPLICATION_RESPONSE = ByteArrayHexStringConverter
			.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000");
	private static final byte[] GET_NEXT_DATA_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000");
	private static final byte[] SIGNATURE_RESPONSE = ByteArrayHexStringConverter.hexStringToByteArray(
			"DCC5F055C2B689A3D5FBAE8ABB9892FF6B0228D05AAA69BBA435324F1E9A6D900C2B6F8DC7D43DD2D9DF47847C7ADF786E99474102E2EA1E19EDF0177221FE349000");

	private static final Random ZERO_RANDOM = new Random() {

		private static final long serialVersionUID = 1L;

		@Override
		public void nextBytes(byte[] bytes) {
			Arrays.fill(bytes, (byte) 0);
		}
	};

	private ExecutorService pool;

	@AfterEach
	public void shutdown() {
		if (pool != null) {
			pool.shutdownNow();
		}
	}

	private ExecutorService newPool(int threads) {
		AtomicInteger count = new AtomicInteger();
		ThreadFactory threadFactory = r -> {
			Thread thread = new Thread(r, "test-pool-" + count.incrementAndGet());
			thread.setDaemon(true);
			return thread;
		};
		pool = Executors.newFixedThreadPool(threads, threadFactory);
		return pool;
	}

	private static ListResponseCard newCard() {
		ListResponseCard card = new ListResponseCard();
		card.add(SELECT_APPLICATION_RESPONSE);
		card.add(GET_NEXT_DATA_RESPONSE);
		card.add(SIGNATURE_RESPONSE);
		return card;
	}

	private static class CountingExecutor implements Executor {

		private final Executor delegate;
		final AtomicInteger tasks = new AtomicInteger();

		CountingExecutor(Executor delegate) {
			this.delegate = delegate;
		}

		@Override
		public void execute(Runnable command) {
			tasks.incrementAndGet();
			delegate.execute(command);
		}
	}

	@Test
	public void testProcessorsRunOnTheExecutor() throws Exception {
		CountingExecutor executor = new CountingExecutor(newPool(3));

		VerifyTrustChainMts7ProcessorFactory processorFactory = new VerifyTrustChainMts7ProcessorFactory(participantPublicKeys, (Provider) null, executor);
		InFlightMts7CardFactory factory = new InFlightMts7CardFactory(processorFactory, ZERO_RANDOM);

		// as many readers as there are threads
		List<Throwable> failures = ConcurrentRunner.run(3, 20, (thread, iteration) -> {
			try (InFlightMts7Card inFlightCard = factory.create(new DefaultMts7Card(newCard()), null)) {
				Mts7Card card = inFlightCard.getMts7Card(0);

				assertTrue(card.isVerifiedPrivateKeyPresent());
				assertTrue(card.isVerifiedTrustChain());
			}
		});

		assertEquals(0, failures.size(), "Unexpected failures: " + failures);
		assertEquals(60, executor.tasks.get());
	}

	@Test
	public void testThreadIsReusedForTheNextCard() throws Exception {
		ExecutorService single = newPool(1);

		VerifyKeyPairMts7ProcessorFactory processorFactory = new VerifyKeyPairMts7ProcessorFactory((Provider) null, single);
		InFlightMts7CardFactory factory = new InFlightMts7CardFactory(processorFactory, ZERO_RANDOM);

		for (int i = 0; i < 10; i++) {
			try (InFlightMts7Card inFlightCard = factory.create(new DefaultMts7Card(newCard()), null)) {
				assertTrue(inFlightCard.getMts7Card(0).isVerifiedPrivateKeyPresent(), "card " + i);
			}
		}
	}

	@Test
	public void testClosingDoesNotDisturbTheNextCardOnTheSameThread() throws Exception {
		ExecutorService single = newPool(1);

		VerifyKeyPairMts7ProcessorFactory processorFactory = new VerifyKeyPairMts7ProcessorFactory((Provider) null, single);
		InFlightMts7CardFactory factory = new InFlightMts7CardFactory(processorFactory, ZERO_RANDOM);

		for (int i = 0; i < 10; i++) {
			// a card which is not read to the end, i.e. the processor is stopped while it waits for input
			ListResponseCard card = new ListResponseCard();
			card.add(SELECT_APPLICATION_RESPONSE);

			assertThrows(IndexOutOfBoundsException.class, () -> factory.create(new DefaultMts7Card(card), null));
		}

		// the (only) thread is not interrupted, nor busy
		try (InFlightMts7Card inFlightCard = factory.create(new DefaultMts7Card(newCard()), null)) {
			Mts7Card card = assertTimeoutPreemptively(Duration.ofSeconds(10), () -> inFlightCard.getMts7Card(0));

			assertTrue(card.isVerifiedPrivateKeyPresent());
		}
	}

	@Test
	public void testRejectedByExecutor() throws Exception {
		Executor rejecting = command -> {
			throw new RejectedExecutionException("full");
		};

		VerifyKeyPairMts7ProcessorFactory processorFactory = new VerifyKeyPairMts7ProcessorFactory((Provider) null, rejecting);
		InFlightMts7CardFactory factory = new InFlightMts7CardFactory(processorFactory, ZERO_RANDOM);

		assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
			assertThrows(RejectedExecutionException.class, () -> factory.create(new DefaultMts7Card(newCard()), null));
		});

		// a processor which could not be started does not make anyone wait for it
		Mts7Processor processor = processorFactory.create();
		assertThrows(RejectedExecutionException.class, processor::start);

		assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
			assertThrows(UnableToVerifyKeyPairException.class, () -> processor.waitForVerify(0));
		});
	}

}
