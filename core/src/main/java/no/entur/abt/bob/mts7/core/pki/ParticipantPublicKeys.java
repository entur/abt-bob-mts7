package no.entur.abt.bob.mts7.core.pki;

import java.security.Provider;
import java.security.Signature;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import no.entur.abt.bob.api.pm.model.JwkPublic;
import no.entur.abt.bob.api.pm.model.ParticipantMetadata;
import no.entur.abt.bob.mts7.core.UnableToConstructIssuerKeyException;

/**
 * 
 * Lazy key cache
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

			Map<Long, Issuer> keys = new HashMap<>(); // thread safe for reading

			for (ParticipantMetadata p : items) {

				List<JwkPublic> mtbPublicKeys = p.getMtbPublicKeys();

				Map<String, IssuerKey> map = new HashMap<>(mtbPublicKeys.size() * 4);

				for (JwkPublic jwkPublic : mtbPublicKeys) {
					map.put(jwkPublic.getKid(), new IssuerKey(jwkPublic));
				}

				Issuer key = new Issuer(p.getOrganisationName(), p.getPid(), map, factory);

				keys.put(p.getPid(), key);
			}

			return new ParticipantPublicKeys(keys);
		}
	}

	public static class IssuerKey {

		private IssuerPublicKey key;

		private final JwkPublic keyMaterial;

		public IssuerKey(JwkPublic keyMaterial) {
			super();
			this.keyMaterial = keyMaterial;
		}

		public IssuerPublicKey getKey() {
			return key;
		}

		public JwkPublic getKeyMaterial() {
			return keyMaterial;
		}

		public void setKey(IssuerPublicKey key) {
			this.key = key;
		}

		public boolean hasKey() {
			return key != null;
		}
	}

	public static class Issuer {

		private final String name;
		private final long pid;
		private final IssuerSignatureFactory factory;

		private Map<String, IssuerKey> keys;

		public Issuer(String name, long pid, Map<String, IssuerKey> map, IssuerSignatureFactory factory) {
			this.name = name;
			this.pid = pid;
			this.keys = map;
			this.factory = factory;
		}

		public IssuerPublicKey getKey(String id) throws UnableToConstructIssuerKeyException {
			IssuerKey issuerKey = keys.get(id);
			if (issuerKey != null) {
				if (!issuerKey.hasKey()) {
					JwkPublic keyMaterial = issuerKey.getKeyMaterial();

					Signature signature = factory.create(keyMaterial);

					IssuerPublicKey key = new IssuerPublicKey(pid, keyMaterial.getKid(), signature);

					issuerKey.setKey(key);
				}

				return issuerKey.getKey();
			}
			return null;
		}

		public String getName() {
			return name;
		}
	}

	private final Map<Long, Issuer> keys;

	public ParticipantPublicKeys(Map<Long, Issuer> keys) {
		this.keys = keys;
	}

	public IssuerPublicKey getIssuerPublicKey(long pid, String kid) throws Exception {
		Issuer key = keys.get(pid);
		if (key != null) {
			return key.getKey(kid);
		}
		return null;
	}

	public String getName(long pid) {
		Issuer key = keys.get(pid);
		if (key != null) {
			return key.getName();
		}
		return null;
	}

}
