package no.entur.abt.bob.mts7.reader.processor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.test.util.ConcurrentRunner;

public class AbstractMts7ProcessorTest {

	private static class Probe extends AbstractMts7Processor {

		Probe() {
			super(new Executor() {
				@Override
				public void execute(Runnable command) {
					throw new IllegalStateException("not used");
				}
			});
		}

		@Override
		protected void process() {
		}

		@Override
		public Mts7Card waitForVerify(long timeout) {
			return null;
		}
	}

	@Test
	public void testCommandAndResponseOfInternalAuthenticateBelongTogether() throws Exception {
		Probe processor = new Probe();

		byte[] commandA = new byte[] { 1 };
		byte[] responseA = new byte[] { 1, 1 };
		byte[] commandB = new byte[] { 2 };
		byte[] responseB = new byte[] { 2, 2 };

		AtomicBoolean done = new AtomicBoolean();

		// somebody (or several) keep giving the processor input, and the processor must never see the command of one call with the response of another
		Thread writer = new Thread(() -> {
			while (!done.get()) {
				processor.onInternalAuthenticate(commandA, responseA);
				processor.onInternalAuthenticate(commandB, responseB);
			}
		});
		writer.setDaemon(true);
		writer.start();

		try {
			List<Throwable> failures = ConcurrentRunner.run(2, 200000, (thread, iteration) -> {
				AbstractMts7Processor.InternalAuthenticate input = processor.internalAuthenticate;
				if (input == null) {
					return;
				}
				if (input.command == commandA) {
					assertSame(responseA, input.response);
				} else {
					assertSame(commandB, input.command);
					assertSame(responseB, input.response);
				}
			});

			assertEquals(0, failures.size(), "Unexpected failures: " + failures.size());
		} finally {
			done.set(true);
			writer.join(5000);
		}
		assertNotNull(processor.internalAuthenticate);
	}

}
