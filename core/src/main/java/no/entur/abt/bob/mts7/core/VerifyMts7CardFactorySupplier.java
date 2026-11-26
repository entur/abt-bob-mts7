package no.entur.abt.bob.mts7.core;

/**
 * Supplies the {@linkplain VerifyMts7CardFactory} for the current issuer keys, which may change over time, for example when new participant metadata is loaded
 * (see {@linkplain no.entur.abt.bob.mts7.core.pki.UpdatableVerifyMts7CardFactorySupplier}).
 */

@FunctionalInterface
public interface VerifyMts7CardFactorySupplier {

	/**
	 * @return the factory for the current issuer keys, which can be shared by all threads
	 */

	VerifyMts7CardFactory getVerifyMts7CardFactory();

}
