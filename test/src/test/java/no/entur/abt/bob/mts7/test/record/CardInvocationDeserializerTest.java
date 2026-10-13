package no.entur.abt.bob.mts7.test.record;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class CardInvocationDeserializerTest {

	@Test
	public void testHandledType() {
		assertEquals(CardInvocation.class, new CardInvocationDeserializer().handledType());
	}

}
