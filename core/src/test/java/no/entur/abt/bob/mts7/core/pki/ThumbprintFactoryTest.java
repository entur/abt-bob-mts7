package no.entur.abt.bob.mts7.core.pki;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.core.IccKeyInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.mtb.IssuerSignatureProtectedHeader;
import no.entur.abt.bob.mts7.mtb.TokenPublicKey;

public class ThumbprintFactoryTest {

	private static IssuerSignatureProtectedHeader header(TokenPublicKey tpk) {
		IssuerSignatureProtectedHeader header = new IssuerSignatureProtectedHeader();
		header.setAlg("ES256");
		header.setTpk(tpk);
		return header;
	}

	private static TokenPublicKey ecKey(String x) {
		TokenPublicKey tpk = new TokenPublicKey();
		tpk.setKty("EC");
		tpk.setCrv("P-256");
		tpk.setX(x);
		tpk.setY("y");
		return tpk;
	}

	@Test
	public void testThumbprint() throws Exception {
		ThumbprintFactory factory = new ThumbprintFactory(null);

		byte[] thumbprint = factory.create(header(ecKey("x")));

		// the first half of SHA-256
		assertEquals(16, thumbprint.length);
		assertArrayEquals(thumbprint, factory.create(header(ecKey("x"))));
		assertFalse(Arrays.equals(thumbprint, factory.create(header(ecKey("other")))));
	}

	@Test
	public void testMissingTokenPublicKeyIsCardSide() throws Exception {
		assertThrows(IccKeyInvalidCardMts7Exception.class, () -> new ThumbprintFactory(null).create(header(null)));
	}

	@Test
	public void testUnknownKeyTypeIsCardSide() throws Exception {
		TokenPublicKey tpk = ecKey("x");
		tpk.setKty("oct");

		assertThrows(IccKeyInvalidCardMts7Exception.class, () -> new ThumbprintFactory(null).create(header(tpk)));
	}

}
