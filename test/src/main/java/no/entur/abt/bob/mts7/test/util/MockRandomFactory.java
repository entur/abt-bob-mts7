package no.entur.abt.bob.mts7.test.util;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEFAULTS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

import java.util.Random;

import org.mockito.MockSettings;
import org.mockito.internal.creation.MockSettingsImpl;

import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * 
 * Mock Random factory
 * 
 */

public class MockRandomFactory {

	public static Random newInstance(String input) {
		return newInstance(ByteArrayHexStringConverter.hexStringToByteArray(input));
	}

	public static Random newInstance(byte[] randomBytes) {
		Random random = mock(Random.class, withSettings().withoutAnnotations());
		doAnswer(invocation -> {
			byte[] bytes = invocation.getArgument(0);
			if (bytes.length != randomBytes.length) {
				throw new IllegalStateException();
			}
			System.arraycopy(randomBytes, 0, bytes, 0, randomBytes.length);

			return null;
		}).when(random).nextBytes(any(byte[].class));

		return random;
	}

	public static MockSettings withSettings() {
		return new MockSettingsImpl<>().defaultAnswer(RETURNS_DEFAULTS);
	}

}
