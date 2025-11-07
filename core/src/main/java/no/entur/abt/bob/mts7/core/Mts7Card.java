package no.entur.abt.bob.mts7.core;

import java.util.Arrays;
import java.util.Objects;

public class Mts7Card {

	private boolean verifiedPrivateKeyPresent;
	private boolean verifiedTrustChain;

	private Integer participantIdentifier;
	private Integer version;
	private byte[] serial;

	private Integer signatureCounter;
	private LifecycleStatus lifeCycleStatus;

	private int maximumCommandApduLength = -1;
	private int maximumResponseApduLength = -1;

	public byte[] thumbprint;

	public boolean isVerifiedPrivateKeyPresent() {
		return verifiedPrivateKeyPresent;
	}

	public void setVerifiedPrivateKeyPresent(boolean verified) {
		this.verifiedPrivateKeyPresent = verified;
	}

	public void setVerifiedTrustChain(boolean trustChainVerified) {
		this.verifiedTrustChain = trustChainVerified;
	}

	public boolean isVerifiedTrustChain() {
		return verifiedTrustChain;
	}

	public Integer getSignatureCounter() {
		return signatureCounter;
	}

	public void setSignatureCounter(Integer signatureCounter) {
		this.signatureCounter = signatureCounter;
	}

	public LifecycleStatus getLifeCycleStatus() {
		return lifeCycleStatus;
	}

	public void setLifeCycleStatus(LifecycleStatus lifeCycleStatus) {
		this.lifeCycleStatus = lifeCycleStatus;
	}

	public Integer getMaximumCommandApduLength() {
		return maximumCommandApduLength;
	}

	public boolean hasMaximumCommandApduLength() {
		return maximumCommandApduLength != -1;
	}

	public void setMaximumCommandApduLength(int maximumCommandApduLength) {
		this.maximumCommandApduLength = maximumCommandApduLength;
	}

	public int getMaximumResponseApduLength() {
		return maximumResponseApduLength;
	}

	public void setMaximumResponseApduLength(int maximumResponseApduLength) {
		this.maximumResponseApduLength = maximumResponseApduLength;
	}

	public Integer getParticipantIdentifier() {
		return participantIdentifier;
	}

	public void setParticipantIdentifier(Integer participantIdentifier) {
		this.participantIdentifier = participantIdentifier;
	}

	public Integer getVersion() {
		return version;
	}

	public void setVersion(Integer version) {
		this.version = version;
	}

	public byte[] getSerial() {
		return serial;
	}

	public void setSerial(byte[] serial) {
		this.serial = serial;
	}

	public void setThumbprint(byte[] thumbprint) {
		this.thumbprint = thumbprint;
	}

	public boolean hasThumprint() {
		return thumbprint != null;
	}

	public boolean hasSerial() {
		return serial != null;
	}

	public byte[] getThumbprint() {
		return thumbprint;
	}

	public boolean hasParticipantIdentifier() {
		return participantIdentifier != null;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(serial);
		result = prime * result + Arrays.hashCode(thumbprint);
		result = prime * result + Objects.hash(lifeCycleStatus, maximumCommandApduLength, maximumResponseApduLength, participantIdentifier, signatureCounter,
				verifiedPrivateKeyPresent, verifiedTrustChain, version);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Mts7Card other = (Mts7Card) obj;
		return lifeCycleStatus == other.lifeCycleStatus && maximumCommandApduLength == other.maximumCommandApduLength
				&& maximumResponseApduLength == other.maximumResponseApduLength && Objects.equals(participantIdentifier, other.participantIdentifier)
				&& Arrays.equals(serial, other.serial) && Objects.equals(signatureCounter, other.signatureCounter)
				&& Arrays.equals(thumbprint, other.thumbprint) && verifiedPrivateKeyPresent == other.verifiedPrivateKeyPresent
				&& verifiedTrustChain == other.verifiedTrustChain && Objects.equals(version, other.version);
	}

}
