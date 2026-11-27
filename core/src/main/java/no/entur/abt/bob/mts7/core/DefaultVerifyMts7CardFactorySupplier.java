package no.entur.abt.bob.mts7.core;

import java.util.Objects;

/**
 * Supplies the same {@linkplain VerifyMts7CardFactory} every time, for issuer keys which do not change (see
 * {@linkplain no.entur.abt.bob.mts7.core.UpdatableVerifyMts7CardFactorySupplier} for issuer keys which do).
 * <p>
 * Instances are thread safe.
 */

public class DefaultVerifyMts7CardFactorySupplier implements VerifyMts7CardFactorySupplier {

	private final VerifyMts7CardFactory verifyMts7CardFactory;

	/**
	 * Constructor.
	 *
	 * @param verifyMts7CardFactory the factory, which can be shared by all threads
	 */

	public DefaultVerifyMts7CardFactorySupplier(VerifyMts7CardFactory verifyMts7CardFactory) {
		this.verifyMts7CardFactory = Objects.requireNonNull(verifyMts7CardFactory, "verifyMts7CardFactory");
	}

	@Override
	public VerifyMts7CardFactory getVerifyMts7CardFactory() {
		return verifyMts7CardFactory;
	}

}
