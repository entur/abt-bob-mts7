package no.entur.abt.bob.mts7.core;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.function.Supplier;

import no.entur.abt.bob.mts7.core.pki.ParticipantPublicKeys;

/**
 * Decides who is to blame for a card whose issuer key is not among the issuer public keys. It may be the card, which is forged, or from an issuer which is not
 * trusted ({@linkplain UnknownIssuerKeyInvalidCardMts7Exception}). Or it may be our keys, which may be out of date, for example because the participant
 * metadata could not be updated after the issuer started to use a new key ({@linkplain OutdatedIssuerKeysException}). The card alone does not tell.
 * <p>
 * Whether the keys are up to date is known by whoever keeps them, so the decision is pluggable: see the built-in policies, which can be combined with
 * {@linkplain #and(UnknownIssuerKeyPolicy)}. Implementations must be thread safe.
 */

@FunctionalInterface
public interface UnknownIssuerKeyPolicy {

	/**
	 * Decide who is to blame for a card whose issuer key is not among the keys.
	 *
	 * @param issuerId the issuer id (iid) from the certificate of the card
	 * @param keyId    the key id (kid) from the certificate of the card
	 * @param keys     the issuer public keys
	 * @return true if the card is to blame, false if the keys may be out of date
	 */

	boolean isCardToBlame(long issuerId, String keyId, ParticipantPublicKeys keys);

	/**
	 * @param other another policy
	 * @return a policy which blames the card only if both this and the other policy do
	 */

	default UnknownIssuerKeyPolicy and(UnknownIssuerKeyPolicy other) {
		Objects.requireNonNull(other, "other");
		return (issuerId, keyId, keys) -> isCardToBlame(issuerId, keyId, keys) && other.isCardToBlame(issuerId, keyId, keys);
	}

	/**
	 * @return a policy which always blames the card, for keys which are known to be complete (the default)
	 */

	static UnknownIssuerKeyPolicy blameCard() {
		return (issuerId, keyId, keys) -> true;
	}

	/**
	 * @return a policy which never blames the card, for keys which may well be incomplete
	 */

	static UnknownIssuerKeyPolicy blameKeys() {
		return (issuerId, keyId, keys) -> false;
	}

	/**
	 * A policy which blames the card only if the keys were confirmed to be up to date recently enough, for example when the participant metadata was last
	 * downloaded or found unchanged.
	 *
	 * @param maximumAge  how long ago the keys may have been confirmed to be up to date
	 * @param confirmedAt when the keys were last confirmed to be up to date, or null if never
	 * @param clock       the clock
	 * @return the policy
	 */

	static UnknownIssuerKeyPolicy blameCardIfConfirmedWithin(Duration maximumAge, Supplier<Instant> confirmedAt, Clock clock) {
		Objects.requireNonNull(maximumAge, "maximumAge");
		Objects.requireNonNull(confirmedAt, "confirmedAt");
		Objects.requireNonNull(clock, "clock");
		if (maximumAge.isNegative()) {
			throw new IllegalArgumentException("Expected a maximum age which is not negative");
		}
		return (issuerId, keyId, keys) -> {
			Instant confirmed = confirmedAt.get();
			return confirmed != null && !confirmed.plus(maximumAge).isBefore(clock.instant());
		};
	}
}
