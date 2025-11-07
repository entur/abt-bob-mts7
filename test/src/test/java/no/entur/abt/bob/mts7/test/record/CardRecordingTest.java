package no.entur.abt.bob.mts7.test.record;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.test.record.bob.Mts7TlvPrettyPrinter;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

public class CardRecordingTest {

	@Test
	public void testRoundtrip() throws Exception {

		CardRecordingFactory factory = new CardRecordingFactory();

		CardRecording cardRecording = new CardRecording();
		List<CardInvocation> invocations = new ArrayList<>();

		TransceiveInvocation transceiveInvocation1 = new TransceiveInvocation();
		transceiveInvocation1.setCommand(ByteArrayHexStringConverter.hexStringToByteArray("00A4040006A00000078101"));
		transceiveInvocation1.setResponse(
				ByteArrayHexStringConverter.hexStringToByteArray("64296E274F10A0000007810101000A0000175F96B61D7A0593030000248A01007F660802020105020201029000"));
		transceiveInvocation1.setDuration(50);
		invocations.add(transceiveInvocation1);

		TransceiveInvocation transceiveInvocation2 = new TransceiveInvocation();
		transceiveInvocation2.setCommand(ByteArrayHexStringConverter.hexStringToByteArray("00CC7F21000000"));
		transceiveInvocation2.setResponse(ByteArrayHexStringConverter.hexStringToByteArray(
				"A26176426131617058F88358B1A663616C6765455332353663696964623130636B69646B31303A3230323330323133636D69766136636E6266703230323330363136543131303233365A6374706BA4636B74796245436363727665502D3235366178782B67524531454B772D63475F37415543306835372D54355759416E51634457597275374A776D4C476756666F6179782B706B516B6A56636832543264615F582D4B5368735141515A306A47485A483179775A47546456646236645141A05840A5D45B265A806B649F19432F05F91FAB5854AEAFCFC1B75A63072B88F2EB35BA5A7A3B53B5FC71A3C3DCC7727E9C8C9845F7DEF2756179D54D111E46E58C46039000"));
		transceiveInvocation2.setDuration(100);
		invocations.add(transceiveInvocation2);

		cardRecording.setInvocations(invocations);
		cardRecording.setRandomValue(new byte[] { 0x01 });
		cardRecording.setDateTime(LocalDateTime.now());

		ByteArrayOutputStream bout = new ByteArrayOutputStream();
		factory.write(cardRecording, bout);

		CardRecording recovered = factory.read(new ByteArrayInputStream(bout.toByteArray()));

		List<CardInvocation> recoveredInvocations = recovered.getInvocations();
		assertEquals(transceiveInvocation1, recoveredInvocations.get(0));

		CardRecordingPrettyPrinter prettyPrinter = CardRecordingPrettyPrinter.newBuilder().withPrettyPrinter(Mts7TlvPrettyPrinter.getInstance()).build();
		prettyPrinter.prettyPrintToStandardOut(recovered);
	}

}
