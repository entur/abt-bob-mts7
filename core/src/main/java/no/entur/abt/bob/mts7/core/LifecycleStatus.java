package no.entur.abt.bob.mts7.core;

public enum LifecycleStatus {

	NO_INFORMATION_GIVEN(0x00),
	INITIALIZATION(0x03),
	OPERATIONAL(0x05),
	TERMINATION(0x12);

	// set to ‘00’ (No information given) for PICC of Compliance Level 1, which does not support
	// in-application life-cycle management
	// • set to ‘03’ (Initialisation state) for not yet personalised PICC (CL2)
	// • set to ‘05’ (Operational state - active) for personalised PICC (CL2)
	// • set to ‘12’ (Termination state) for decommissioned PICC (CL2)
	;

	private final int code;

	private LifecycleStatus(int code) {
		this.code = code;
	}

	public int getCode() {
		return code;
	}

	public static LifecycleStatus parse(int v) {
		switch (v) {
		case 0x00:
			return NO_INFORMATION_GIVEN;
		}
		return null;
	}
}
