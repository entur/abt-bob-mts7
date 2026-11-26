package no.entur.abt.bob.mts7.core;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;

public class DefaultVerifyMts7CardFactorySupplierTest {

	@Test
	public void testSuppliesTheSameFactory() throws Exception {
		VerifyMts7CardFactory factory = new VerifyMts7CardFactory(ParticipantPublicKeys.newBuilder().build());

		VerifyMts7CardFactorySupplier supplier = new DefaultVerifyMts7CardFactorySupplier(factory);

		assertSame(factory, supplier.getVerifyMts7CardFactory());
		assertSame(factory, supplier.getVerifyMts7CardFactory());
	}

	@Test
	public void testFactoryIsRequired() {
		assertThrows(NullPointerException.class, () -> new DefaultVerifyMts7CardFactorySupplier(null));
	}

}
