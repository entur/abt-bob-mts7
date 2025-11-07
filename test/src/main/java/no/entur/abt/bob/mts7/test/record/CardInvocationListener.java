package no.entur.abt.bob.mts7.test.record;

public interface CardInvocationListener {

	ConnectInvocation onConnect();

	CloseInvocation onClose();

	TransceiveInvocation onTransceive(byte[] command);

}
