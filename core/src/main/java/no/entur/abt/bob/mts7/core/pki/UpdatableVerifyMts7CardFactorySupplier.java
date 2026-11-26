package no.entur.abt.bob.mts7.core.pki;

import java.security.Provider;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import no.entur.abt.bob.api.pm.model.MtbJwkPublic;
import no.entur.abt.bob.api.pm.model.ParticipantMetadata;
import no.entur.abt.bob.mts7.core.UnableToConstructIssuerKeyException;
import no.entur.abt.bob.mts7.core.VerifyMts7CardFactory;
import no.entur.abt.bob.mts7.core.VerifyMts7CardFactorySupplier;

/**
 * Holds the current {@linkplain VerifyMts7CardFactory}, which verifies MTS7 cards against the issuer public keys (root keys) of a participant metadata set, and
 * replaces it when a new set is loaded (see {@linkplain #update(List)}).
 * <p>
 * The factory never trusts unknown root keys: a card whose root key is not in the set is rejected. Until a set has been loaded there are no issuer keys, so
 * every card is rejected. A new set replaces the factory only when it has changed, so that the factory in use keeps the issuer keys it has already created. A
 * key which is no longer in the set is no longer used (key rollover).
 * <p>
 * Before a new set is used, all of its issuer keys are created, and the set is checked; it is refused if
 * <ul>
 * <li>fewer than a minimum number of its issuer keys can be used, so that a set of keys which cannot be used (garbage) is never used,</li>
 * <li>fewer than a minimum number of participants have an issuer key which can be used,</li>
 * <li>a required participant does not have an issuer key which can be used, or</li>
 * <li>more than a maximum number of its issuer keys cannot be used, so that a few keys which cannot be used do not stop an update, but many do.</li>
 * </ul>
 * A card whose issuer key cannot be used is a problem on our side ({@linkplain UnableToConstructIssuerKeyException}), not an invalid card.
 * <p>
 * Instances are thread safe.
 */

public class UpdatableVerifyMts7CardFactorySupplier implements VerifyMts7CardFactorySupplier {

	private static final Logger LOGGER = LoggerFactory.getLogger(UpdatableVerifyMts7CardFactorySupplier.class);

	/**
	 * By default, a set must have at least one issuer key which can be used.
	 */

	public static final int DEFAULT_MINIMUM_VALID_KEYS = 1;

	/**
	 * By default, there is no limit to the number of issuer keys which cannot be used.
	 */

	public static final int DEFAULT_MAXIMUM_INVALID_KEYS = Integer.MAX_VALUE;

	/**
	 * By default, a set must have at least one participant with an issuer key which can be used.
	 */

	public static final int DEFAULT_MINIMUM_PARTICIPANTS = 1;

	public static Builder newBuilder() {
		return new Builder();
	}

	public static class Builder {

		private Provider provider;
		private int minimumValidKeys = DEFAULT_MINIMUM_VALID_KEYS;
		private int maximumInvalidKeys = DEFAULT_MAXIMUM_INVALID_KEYS;
		private int minimumParticipants = DEFAULT_MINIMUM_PARTICIPANTS;
		private Set<Long> requiredParticipants = new TreeSet<>();

		/**
		 * @param provider security provider (for signatures), or null for the default
		 * @return this builder
		 */

		public Builder withProvider(Provider provider) {
			this.provider = provider;
			return this;
		}

		/**
		 * @param minimumValidKeys the minimum number of issuer keys of a set which can be used; at least 1
		 * @return this builder
		 */

		public Builder withMinimumValidKeys(int minimumValidKeys) {
			this.minimumValidKeys = minimumValidKeys;
			return this;
		}

		/**
		 * @param maximumInvalidKeys the maximum number of issuer keys of a set which cannot be used; at least 0
		 * @return this builder
		 */

		public Builder withMaximumInvalidKeys(int maximumInvalidKeys) {
			this.maximumInvalidKeys = maximumInvalidKeys;
			return this;
		}

		/**
		 * @param minimumParticipants the minimum number of participants of a set with an issuer key which can be used; at least 1
		 * @return this builder
		 */

		public Builder withMinimumParticipants(int minimumParticipants) {
			this.minimumParticipants = minimumParticipants;
			return this;
		}

		/**
		 * @param requiredParticipants ids of participants which a set must have, each with an issuer key which can be used
		 * @return this builder
		 */

		public Builder withRequiredParticipants(Collection<Long> requiredParticipants) {
			this.requiredParticipants.addAll(requiredParticipants);
			return this;
		}

		/**
		 * @param pid id of a participant which a set must have, with an issuer key which can be used
		 * @return this builder
		 */

		public Builder withRequiredParticipant(long pid) {
			this.requiredParticipants.add(pid);
			return this;
		}

		/**
		 * @return the supplier, without a set (so it rejects every card until a set is loaded)
		 * @throws IllegalArgumentException if a limit is out of range
		 */

		public UpdatableVerifyMts7CardFactorySupplier build() {
			if (minimumValidKeys < 1) {
				// a set of keys which cannot be used would be accepted
				throw new IllegalArgumentException("The minimum number of valid keys must be at least 1, not " + minimumValidKeys);
			}
			if (maximumInvalidKeys < 0) {
				throw new IllegalArgumentException("The maximum number of invalid keys must be at least 0, not " + maximumInvalidKeys);
			}
			if (minimumParticipants < 1) {
				throw new IllegalArgumentException("The minimum number of participants must be at least 1, not " + minimumParticipants);
			}
			return new UpdatableVerifyMts7CardFactorySupplier(provider, minimumValidKeys, maximumInvalidKeys, minimumParticipants, requiredParticipants);
		}
	}

	private final Provider provider;
	private final int minimumValidKeys;
	private final int maximumInvalidKeys;
	private final int minimumParticipants;
	private final Set<Long> requiredParticipants;

	// replaced as a whole, so that the set, the keys and the factory always belong together
	private volatile Current current;

	/**
	 * Constructor, with the default limits (see {@linkplain #newBuilder()} for others).
	 *
	 * @param provider security provider (for signatures), or null for the default
	 */

	public UpdatableVerifyMts7CardFactorySupplier(Provider provider) {
		this(provider, DEFAULT_MINIMUM_VALID_KEYS, DEFAULT_MAXIMUM_INVALID_KEYS, DEFAULT_MINIMUM_PARTICIPANTS, Collections.<Long>emptySet());
	}

	protected UpdatableVerifyMts7CardFactorySupplier(Provider provider, int minimumValidKeys, int maximumInvalidKeys, int minimumParticipants,
			Set<Long> requiredParticipants) {
		this.provider = provider;
		this.minimumValidKeys = minimumValidKeys;
		this.maximumInvalidKeys = maximumInvalidKeys;
		this.minimumParticipants = minimumParticipants;
		this.requiredParticipants = Collections.unmodifiableSet(new TreeSet<>(requiredParticipants));
		this.current = build(null);
	}

	/**
	 * @return the factory for the current issuer keys, which can be shared by all threads; it rejects every card until a set has been loaded
	 */

	@Override
	public VerifyMts7CardFactory getVerifyMts7CardFactory() {
		return current.factory;
	}

	/**
	 * @return the current issuer keys, as used by {@linkplain #getVerifyMts7CardFactory()} (empty until a set has been loaded)
	 */

	public ParticipantPublicKeys getParticipantPublicKeys() {
		return current.keys;
	}

	public int getMinimumValidKeys() {
		return minimumValidKeys;
	}

	public int getMaximumInvalidKeys() {
		return maximumInvalidKeys;
	}

	public int getMinimumParticipants() {
		return minimumParticipants;
	}

	/**
	 * @return the ids of the participants which a set must have, each with an issuer key which can be used
	 */

	public Set<Long> getRequiredParticipants() {
		return requiredParticipants;
	}

	/**
	 * Use a newly loaded participant metadata set. Nothing changes if the set is equal to the one in use.
	 * <p>
	 * All of the issuer keys of the set are created, each key which cannot be used is logged, and the set is checked (see the class documentation).
	 *
	 * @param participants the participants of the (verified) set
	 * @throws IllegalArgumentException if the set does not pass the checks; the issuer keys in use are kept
	 */

	public synchronized void update(List<ParticipantMetadata> participants) {
		if (participants.equals(current.participants)) {
			LOGGER.debug("Participant metadata unchanged, keeping the issuer keys in use");
			return;
		}
		Current updated = build(Collections.unmodifiableList(new ArrayList<>(participants)));

		int valid = 0;
		int invalid = 0;
		Set<Long> participantsWithValidKeys = new TreeSet<>();
		for (ParticipantPublicKeys.Issuer issuer : updated.keys.getIssuers()) {
			List<UnableToConstructIssuerKeyException> failures = issuer.createKeys();
			for (UnableToConstructIssuerKeyException e : failures) {
				LOGGER.warn("Issuer key which cannot be used: {}", e.getMessage(), e.getCause());
			}
			List<ParticipantPublicKeys.IssuerKey> unsupported = issuer.getUnsupportedKeys();
			for (ParticipantPublicKeys.IssuerKey key : unsupported) {
				LOGGER.warn("Issuer key which cannot be used: unsupported type of key {} for participant {}", key.getKeyId(), issuer.getPid());
			}
			int issuerInvalid = failures.size() + unsupported.size();
			int issuerValid = issuer.getKeyIds().size() - issuerInvalid;

			valid += issuerValid;
			invalid += issuerInvalid;
			if (issuerValid > 0) {
				participantsWithValidKeys.add(issuer.getPid());
			}
		}

		if (valid < minimumValidKeys) {
			throw new IllegalArgumentException("The participant metadata has " + valid + " issuer keys which can be used, at least " + minimumValidKeys
					+ " are required; keeping the issuer keys in use");
		}
		if (participantsWithValidKeys.size() < minimumParticipants) {
			throw new IllegalArgumentException("The participant metadata has " + participantsWithValidKeys.size()
					+ " participants with issuer keys which can be used, at least " + minimumParticipants + " are required; keeping the issuer keys in use");
		}
		Set<Long> missing = new TreeSet<>(requiredParticipants);
		missing.removeAll(participantsWithValidKeys);
		if (!missing.isEmpty()) {
			throw new IllegalArgumentException("The participant metadata has no issuer keys which can be used for the required participants " + missing
					+ "; keeping the issuer keys in use");
		}
		if (invalid > maximumInvalidKeys) {
			throw new IllegalArgumentException("The participant metadata has " + invalid + " issuer keys which cannot be used, at most " + maximumInvalidKeys
					+ " are accepted; keeping the issuer keys in use");
		}
		current = updated;
		LOGGER.info("Issuer keys updated: {} participants ({} with issuer keys which can be used), {} issuer keys which can be used, {} which cannot",
				participants.size(), participantsWithValidKeys.size(), valid, invalid);
	}

	/**
	 * @param participants the set, or null if none has been loaded yet
	 */

	private Current build(List<ParticipantMetadata> participants) {
		try {
			ParticipantPublicKeys keys = ParticipantPublicKeys.newBuilder()
					.withProvider(provider)
					.withParticipants(withKeysOnly(participants != null ? participants : Collections.<ParticipantMetadata>emptyList()))
					.build();
			// never trust unknown root keys, not even before a set has been loaded
			return new Current(participants, keys, new VerifyMts7CardFactory(keys, provider, false));
		} catch (Exception e) {
			throw new IllegalStateException("Unable to create issuer keys", e);
		}
	}

	/**
	 * @return the participants with only what is needed for the issuer keys, one per participant id
	 */

	private static List<ParticipantMetadata> withKeysOnly(List<ParticipantMetadata> participants) {
		Map<Long, ParticipantMetadata> result = new LinkedHashMap<>();
		for (ParticipantMetadata participant : participants) {
			List<MtbJwkPublic> keys = participant.getMtbPublicKeys() == null ? Collections.<MtbJwkPublic>emptyList() : participant.getMtbPublicKeys();
			result.put(participant.getPid(),
					new ParticipantMetadata().pid(participant.getPid()).organisationName(participant.getOrganisationName()).mtbPublicKeys(keys));
		}
		return new ArrayList<>(result.values());
	}

	private static final class Current {

		private final List<ParticipantMetadata> participants;
		private final ParticipantPublicKeys keys;
		private final VerifyMts7CardFactory factory;

		private Current(List<ParticipantMetadata> participants, ParticipantPublicKeys keys, VerifyMts7CardFactory factory) {
			this.participants = participants;
			this.keys = keys;
			this.factory = factory;
		}
	}

}
