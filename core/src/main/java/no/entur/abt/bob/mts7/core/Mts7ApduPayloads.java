package no.entur.abt.bob.mts7.core;

import java.util.Arrays;

/**
 * 
 * DTO for holding the interesting payloads from the exchanged APDUs.
 * 
 */

public class Mts7ApduPayloads {

	private byte[] tagId;

	private byte[] selectApplicationOutput;
	private byte[] getDataOutput;

	private byte[] internalAuthenticateInput;
	private byte[] internalAuthenticateOutput;

	public byte[] getGetDataOutput() {
		return getDataOutput;
	}

	public boolean hasGetDataOutput() {
		return getDataOutput != null;
	}

	public void setGetDataOutput(byte[] mtb) {
		this.getDataOutput = mtb;
	}

	public boolean hasInternalAuthenticateOutput() {
		return internalAuthenticateOutput != null;
	}

	public void setInternalAuthenticateOutput(byte[] challengeInput) {
		this.internalAuthenticateOutput = challengeInput;
	}

	public byte[] getInternalAuthenticateInput() {
		return internalAuthenticateInput;
	}

	public void setInternalAuthenticateInput(byte[] challengeOutput) {
		this.internalAuthenticateInput = challengeOutput;
	}

	public void setSelectApplicationOutput(byte[] selectApplicationResponse) {
		this.selectApplicationOutput = selectApplicationResponse;
	}

	public byte[] getSelectApplicationOutput() {
		return selectApplicationOutput;
	}

	public boolean hasSelectApplicationOutput() {
		return selectApplicationOutput != null;
	}

	public byte[] getInternalAuthenticateOutput() {
		return internalAuthenticateOutput;
	}

	public void setTagId(byte[] tagId) {
		this.tagId = tagId;
	}

	public byte[] getTagId() {
		return tagId;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(getDataOutput);
		result = prime * result + Arrays.hashCode(internalAuthenticateInput);
		result = prime * result + Arrays.hashCode(internalAuthenticateOutput);
		result = prime * result + Arrays.hashCode(selectApplicationOutput);
		result = prime * result + Arrays.hashCode(tagId);
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
		Mts7ApduPayloads other = (Mts7ApduPayloads) obj;
		return Arrays.equals(getDataOutput, other.getDataOutput) && Arrays.equals(internalAuthenticateInput, other.internalAuthenticateInput)
				&& Arrays.equals(internalAuthenticateOutput, other.internalAuthenticateOutput)
				&& Arrays.equals(selectApplicationOutput, other.selectApplicationOutput) && Arrays.equals(tagId, other.tagId);
	}

}
