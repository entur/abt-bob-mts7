package no.entur.abt.bob.mts7.core.pki;

import java.security.Provider;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import no.entur.abt.bob.api.pm.model.MtbJwkPublic;
import no.entur.abt.bob.api.pm.model.ParticipantMetadata;
import no.entur.abt.bob.mts7.core.UnableToConstructIssuerKeyException;

/**
 * 
 * Lazy key cache.
 * <p>
 * Instances are thread safe, so a single instance should be shared by all threads. The keys are created when first used; see
 * {@linkplain no.entur.abt.bob.mts7.core.warmup.Mts7Warmup} for creating them in advance.
 * 
 */

public class ParticipantPublicKeys {

	public static Builder newBuilder() {
		return new Builder();
	}

	public static class Builder {

		private List<ParticipantMetadata> items = new ArrayList<>();
		private Provider provider;

		public Builder withProvider(Provider provider) {
			this.provider = provider;
			return this;
		}

		public Builder withParticipants(List<ParticipantMetadata> items) {
			this.items = items;
			return this;
		}

		public Builder withParticipant(ParticipantMetadata p) {
			items.add(p);

			return this;
		}

		public ParticipantPublicKeys build() throws Exception {
			IssuerSignatureFactory factory = new IssuerSignatureFactory(provider);

			// not modified after it has been built, so it is safe to read from several threads
			Map<Long, Issuer> keys = new HashMap<>();

			for (ParticipantMetadata p : items) {

				List<MtbJwkPublic> mtbPublicKeys = p.getMtbPublicKeys();

				Map<String, IssuerKey> map = new HashMap<>(mtbPublicKeys.size() * 4);

				for (MtbJwkPublic jwkPublic : mtbPublicKeys) {
					map.put(jwkPublic.getKid(), new IssuerKey(jwkPublic));
				}

				Issuer key = new Issuer(p.getOrganisationName(), p.getPid(), map, factory);

				keys.put(p.getPid(), key);
			}

			return new ParticipantPublicKeys(keys);
		}
	}

	public static class IssuerKey {

		// created on demand, and visible to all threads when set
		private volatile IssuerPublicKey key;

		// the type of key is not supported, which will not change, so there is no point in trying again
		private volatile boolean unsupported;

		private final MtbJwkPublic keyMaterial;

		public IssuerKey(MtbJwkPublic keyMaterial) {
			super();
			this.keyMaterial = keyMaterial;
		}

		public IssuerPublicKey getKey() {
			return key;
		}

		public MtbJwkPublic getKeyMaterial() {
			return keyMaterial;
		}

		public void setKey(IssuerPublicKey key) {
			this.key = key;
		}

		public boolean hasKey() {
			return key != null;
		}

		public boolean isUnsupported() {
			return unsupported;
		}

		public void setUnsupported(boolean unsupported) {
			this.unsupported = unsupported;
		}
	}

	public static class Issuer {

		private final String name;
		private final long pid;
		private final IssuerSignatureFactory factory;

		// not modified after it has been built, so it is safe to read from several threads
		private final Map<String, IssuerKey> keys;

		public Issuer(String name, long pid, Map<String, IssuerKey> map, IssuerSignatureFactory factory) {
			this.name = name;
			this.pid = pid;
			this.keys = map;
			this.factory = factory;
		}

		public IssuerPublicKey getKey(String id) throws UnableToConstructIssuerKeyException {
			IssuerKey issuerKey = keys.get(id);
			if (issuerKey == null) {
				return null;
			}

			IssuerPublicKey key = issuerKey.getKey();
			if (key == null && !issuerKey.isUnsupported()) {
				// creating a key has no side effects, and the result is thread safe, so there is no need to prevent several threads from creating one at the
				// same time: all of the keys are equivalent
				key = factory.createIssuerPublicKey(pid, issuerKey.getKeyMaterial());
				if (key != null) {
					issuerKey.setKey(key);
				} else {
					issuerKey.setUnsupported(true);
				}
			}
			return key;
		}

		/**
		 * @param id key id
		 * @return whether the participant has a key with this id, also if the key cannot be used (see {@linkplain #getKey(String)})
		 */

		public boolean hasKey(String id) {
			return keys.containsKey(id);
		}

		/**
		 * @return the ids of the keys of the participant (a copy)
		 */

		public Set<String> getKeyIds() {
			return new HashSet<>(keys.keySet());
		}

		public String getName() {
			return name;
		}
	}

	private final Map<Long, Issuer> keys;

	public ParticipantPublicKeys(Map<Long, Issuer> keys) {
		this.keys = keys;
	}

	/**
	 * @param pid participant id
	 * @param kid key id
	 * @return the key, or null if the participant or key is unknown, or if the type of key is not supported (see
	 *         {@linkplain #hasIssuerPublicKey(long, String)})
	 * @throws UnableToConstructIssuerKeyException if the key is known, but could not be created (a problem on our side)
	 */

	public IssuerPublicKey getIssuerPublicKey(long pid, String kid) throws UnableToConstructIssuerKeyException {
		Issuer key = keys.get(pid);
		if (key != null) {
			return key.getKey(kid);
		}
		return null;
	}

	/**
	 * Whether the key is among the keys of the participants. This is also true for a key which cannot be used (not supported), for which
	 * {@linkplain #getIssuerPublicKey(long, String)} returns null: such a key is known, so it is not the same as a key which nobody has heard of.
	 *
	 * @param pid participant id
	 * @param kid key id
	 * @return whether the participant is known, and has a key with this id
	 */

	public boolean hasIssuerPublicKey(long pid, String kid) {
		Issuer key = keys.get(pid);
		return key != null && key.hasKey(kid);
	}

	/**
	 * @return the ids of the participants (a copy)
	 */

	public Set<Long> getParticipantIds() {
		return new HashSet<>(keys.keySet());
	}

	/**
	 * @param pid participant id
	 * @return the participant, or null if unknown
	 */

	public Issuer getIssuer(long pid) {
		return keys.get(pid);
	}

	public String getName(long pid) {
		Issuer key = keys.get(pid);
		if (key != null) {
			return key.getName();
		}
		return null;
	}

}
