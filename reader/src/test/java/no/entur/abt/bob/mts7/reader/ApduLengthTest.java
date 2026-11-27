package no.entur.abt.bob.mts7.reader;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import no.entur.abt.bob.mts7.api.InsufficientCardCommandsException;
import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.api.Mts7Exception;
import no.entur.abt.bob.mts7.api.UnexpectedCardResponseException;
import no.entur.abt.bob.mts7.core.KeyPairInvalidCardMts7Exception;
import no.entur.abt.bob.mts7.core.LenientMts7ApduPayloadsFactory;
import no.entur.abt.bob.mts7.core.Mts7ApduPayloads;
import no.entur.abt.bob.mts7.core.Mts7ApduPayloadsFactory;
import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.core.VerifyKeyPairMts7CardFactory;
import no.entur.abt.bob.mts7.reader.processor.Mts7Processor;
import no.entur.abt.bob.mts7.reader.processor.VerifyKeyPairMts7ProcessorFactory;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchanges;
import no.entur.abt.bob.mts7.simple.reader.Mts7ApduExchangesFactory;
import no.entur.abt.bob.mts7.simple.reader.Mts7Exchange;
import no.entur.abt.bob.mts7.test.SimulatedCard;
import no.entur.abt.bob.mts7.test.record.CardPlayback;
import no.entur.abt.bob.mts7.test.record.CardRecording;
import no.entur.abt.bob.mts7.test.record.CardRecordingFactory;
import no.entur.abt.bob.mts7.test.record.TransceiveInvocation;
import no.entur.abt.bob.mts7.test.util.MockRandomFactory;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * The reader sends GET NEXT DATA with an extended Le, which saves GET RESPONSE round trips for cards which support extended length. Extended length support is
 * optional for the PICC (MTS7 section 3.1.4), and a PICC which does not support it rejects the command with 6700 (wrong length). Then the reader repeats the
 * command with a short Le, and reads the rest of a longer response using response chaining (MTS7 section 2.1).
 * <p>
 * The cards seen so far are replayed from recordings (see {@linkplain CardRecordingIntegrationTest}), checking that the commands are exactly as recorded. The
 * cases which these cards do not cover are simulated, using data from the recordings.
 */

public class ApduLengthTest extends AbstractExecutorTest {

	private static final byte[] GET_NEXT_DATA_EXTENDED_LENGTH = Mts7ApduExchangesFactory.GET_NEXT_DATA_COMMAND;
	private static final byte[] GET_NEXT_DATA_SHORT_LENGTH = Mts7ApduExchangesFactory.GET_NEXT_DATA_SHORT_LENGTH_COMMAND;
	private static final byte[] GET_RESPONSE_SHORT_LENGTH = Mts7ApduExchangesFactory.GET_RESPONSE_SHORT_LENGTH_COMMAND;

	private static final byte[] REFERENCED_DATA_NOT_FOUND = { 0x6A, (byte) 0x88 };

	// accepts an extended Le, and returns the whole MTB (258 bytes) in a single response
	private static CardRecording participant10;

	// rejects an extended Le with 6700, and returns the MTB (232 bytes) in a single response to a short Le
	private static CardRecording participant36;

	@BeforeAll
	public static void readRecordings() throws Exception {
		CardRecordingFactory factory = new CardRecordingFactory();

		participant10 = factory.read("/recordings/participant-10-0000175F96B61D.json");
		participant36 = factory.read("/recordings/participant-36-000114C5C31EBB.json");
	}

	private static byte[] getResponse(CardRecording recording, int index) {
		return recording.getTransceiveInvocations().get(index).getResponse();
	}

	private Mts7ApduExchanges read(Mts7Exchange card, Random random) throws Exception {
		return new Mts7ApduExchangesFactory(random).createCard(card, null);
	}

	private Mts7ApduExchanges readWithProcessor(Mts7Exchange card, Random random) throws Exception {
		Mts7Processor processor = new VerifyKeyPairMts7ProcessorFactory(executor).create();
		try {
			return new ProcessorMts7ApduExchangesFactory(random).create(card, processor, null);
		} finally {
			processor.close();
		}
	}

	private static Random random() {
		return MockRandomFactory.newInstance(new byte[32]);
	}

	/**
	 * Check that the commands between select and internal authenticate are as expected, and that the MTB is read in full from the recorded exchanges.
	 */

	private static void assertRead(List<byte[]> commands, Mts7ApduExchanges exchanges, byte[] mtb, byte[]... expectedCommands) throws Exception {
		// select, the expected commands, internal authenticate
		assertEquals(expectedCommands.length + 2, commands.size());
		for (int i = 0; i < expectedCommands.length; i++) {
			assertArrayEquals(expectedCommands[i], commands.get(i + 1), "command " + (i + 1));
		}
		assertEquals(0x88, commands.get(commands.size() - 1)[1] & 0xFF);

		assertEquals(commands.size(), exchanges.getExchanges().size());
		assertArrayEquals(mtb, new Mts7ApduPayloadsFactory().createCard(exchanges).getGetDataOutput());
		assertArrayEquals(mtb, new LenientMts7ApduPayloadsFactory().createCard(exchanges).getGetDataOutput());
	}

	/**
	 * Replay the recording with both the plain and the processor based reader, and check that the MTB is read and that the private key of the card is verified.
	 */

	private void assertRecordingRead(CardRecording recording, byte[]... expectedCommands) throws Exception {
		List<TransceiveInvocation> invocations = recording.getTransceiveInvocations();

		// the response to the last get next data, without the status bytes
		byte[] getNextDataResponse = invocations.get(invocations.size() - 2).getResponse();
		byte[] mtb = Arrays.copyOf(getNextDataResponse, getNextDataResponse.length - 2);

		List<byte[]> recordedCommands = new ArrayList<>();
		for (TransceiveInvocation invocation : invocations) {
			recordedCommands.add(invocation.getCommand());
		}

		// with the recorded random value, the challenge of internal authenticate is the same too, so all the commands must be exactly as recorded
		CardPlayback card = recording.toExactPlayback(true);
		Mts7ApduExchanges exchanges = read(new DefaultMts7Card(card), MockRandomFactory.newInstance(recording.getRandomValue()));
		assertTrue(card.isComplete(), "all the recorded commands were sent");
		assertRead(recordedCommands, exchanges, mtb, expectedCommands);
		assertVerifiedPrivateKey(exchanges);

		CardPlayback processorCard = recording.toExactPlayback(true);
		Mts7ApduExchanges processorExchanges = readWithProcessor(new DefaultMts7Card(processorCard), MockRandomFactory.newInstance(recording.getRandomValue()));
		assertTrue(processorCard.isComplete(), "all the recorded commands were sent");
		assertRead(recordedCommands, processorExchanges, mtb, expectedCommands);
		assertVerifiedPrivateKey(processorExchanges);
	}

	private static void assertVerifiedPrivateKey(Mts7ApduExchanges exchanges) throws Exception {
		Mts7ApduPayloads payloads = new Mts7ApduPayloadsFactory().createCard(exchanges);

		assertTrue(new VerifyKeyPairMts7CardFactory().create(payloads).isVerifiedPrivateKeyPresent());
	}

	@Test
	public void testParticipant10Card() throws Exception {
		// extended length, so the whole MTB in a single response
		assertRecordingRead(participant10, GET_NEXT_DATA_EXTENDED_LENGTH);
	}

	@Test
	public void testParticipant36Card() throws Exception {
		// rejected extended length, then short length with an MTB which fits in a single response
		assertRecordingRead(participant36, GET_NEXT_DATA_EXTENDED_LENGTH, GET_NEXT_DATA_SHORT_LENGTH);
	}

	@Test
	public void testCardWithoutExtendedLengthSupportAndLongMtb() throws Exception {
		// like the participant 36 card, but with the longer MTB of the participant 10 card, which needs response chaining, also with short length
		byte[] getNextDataResponse = getResponse(participant10, 1);
		byte[] mtb = Arrays.copyOf(getNextDataResponse, getNextDataResponse.length - 2);
		assertEquals(258, mtb.length);

		SimulatedCard card = new SimulatedCard(participant36, false, 256, mtb);
		assertRead(card.getCommands(), read(new DefaultMts7Card(card), random()), mtb, GET_NEXT_DATA_EXTENDED_LENGTH, GET_NEXT_DATA_SHORT_LENGTH,
				GET_RESPONSE_SHORT_LENGTH);

		SimulatedCard processorCard = new SimulatedCard(participant36, false, 256, mtb);
		assertRead(processorCard.getCommands(), readWithProcessor(new DefaultMts7Card(processorCard), random()), mtb, GET_NEXT_DATA_EXTENDED_LENGTH,
				GET_NEXT_DATA_SHORT_LENGTH, GET_RESPONSE_SHORT_LENGTH);
	}

	/**
	 * A card which rejects both extended and short length is not tried again.
	 */

	private static class WrongLengthCard extends SimulatedCard {

		public WrongLengthCard() {
			super(participant36, false, 256, new byte[0]);
		}

		@Override
		public byte[] transceive(byte[] command) throws IOException {
			if ((command[1] & 0xFF) == 0xCC) {
				getCommands().add(command);
				return SimulatedCard.WRONG_LENGTH;
			}
			return super.transceive(command);
		}
	}

	@Test
	public void testCardWhichRejectsShortLength() throws Exception {
		// not provably the fault of the card, as the examples of GET NEXT DATA in MTS7 have an extended Le, which the card need not support
		WrongLengthCard card = new WrongLengthCard();
		InsufficientCardCommandsException e = assertThrows(InsufficientCardCommandsException.class, () -> read(new DefaultMts7Card(card), random()));
		assertArrayEquals(GET_NEXT_DATA_SHORT_LENGTH, e.getCommand());
		assertEquals(3, card.getCommands().size());

		WrongLengthCard processorCard = new WrongLengthCard();
		e = assertThrows(InsufficientCardCommandsException.class, () -> readWithProcessor(new DefaultMts7Card(processorCard), random()));
		assertArrayEquals(GET_NEXT_DATA_SHORT_LENGTH, e.getCommand());
		assertEquals(3, processorCard.getCommands().size());
	}

	/**
	 * Other errors than wrong length are not a reason to try short length.
	 */

	private static class NoMtbCard extends SimulatedCard {

		public NoMtbCard() {
			super(participant10, true, 1024, new byte[0]);
		}

		@Override
		public byte[] transceive(byte[] command) throws IOException {
			if ((command[1] & 0xFF) == 0xCC) {
				getCommands().add(command);
				return REFERENCED_DATA_NOT_FOUND;
			}
			return super.transceive(command);
		}
	}

	@Test
	public void testCardWithoutMtb() throws Exception {
		NoMtbCard card = new NoMtbCard();
		UnexpectedCardResponseException e = assertThrows(UnexpectedCardResponseException.class, () -> read(new DefaultMts7Card(card), random()));
		assertArrayEquals(GET_NEXT_DATA_EXTENDED_LENGTH, e.getCommand());
		assertEquals(2, card.getCommands().size());

		NoMtbCard processorCard = new NoMtbCard();
		e = assertThrows(UnexpectedCardResponseException.class, () -> readWithProcessor(new DefaultMts7Card(processorCard), random()));
		assertArrayEquals(GET_NEXT_DATA_EXTENDED_LENGTH, e.getCommand());
		assertEquals(2, processorCard.getCommands().size());
	}

	/**
	 * A card which does not return its application-related data (6E) in the select application response, as it need not (MTS7 section 4.1.1), but in the
	 * response to GET DATA of it.
	 */

	private static class ApplicationRelatedDataCard extends SimulatedCard {

		private final byte[] applicationRelatedData;

		public ApplicationRelatedDataCard(byte[] selectApplicationResponse) {
			super(selectApplicationResponse, true, 1024, mtb(participant10), lastResponse(participant10));
			// the 6E nested in the 64 of the recorded select application response, with the status word
			byte[] recorded = getResponse(participant10, 0);
			this.applicationRelatedData = Arrays.copyOfRange(recorded, 2, recorded.length);
		}

		@Override
		public byte[] transceive(byte[] command) throws IOException {
			if (Arrays.equals(command, Mts7ApduExchangesFactory.GET_APPLICATION_RELATED_DATA_COMMAND)) {
				getCommands().add(command);
				return applicationRelatedData;
			}
			return super.transceive(command);
		}
	}

	private static byte[] mtb(CardRecording recording) {
		byte[] getNextDataResponse = getResponse(recording, 1);
		return Arrays.copyOf(getNextDataResponse, getNextDataResponse.length - 2);
	}

	private static byte[] lastResponse(CardRecording recording) {
		List<TransceiveInvocation> invocations = recording.getTransceiveInvocations();
		return invocations.get(invocations.size() - 1).getResponse();
	}

	@Test
	public void testCardWithoutFileManagementData() throws Exception {
		// an empty response, and a File Control Information template without the application-related data
		for (String select : new String[] { "9000", "6F038401009000" }) {
			ApplicationRelatedDataCard card = new ApplicationRelatedDataCard(ByteArrayHexStringConverter.hexStringToByteArray(select));
			Mts7ApduExchanges exchanges = read(new DefaultMts7Card(card), MockRandomFactory.newInstance(participant10.getRandomValue()));

			assertArrayEquals(Mts7ApduExchangesFactory.GET_APPLICATION_RELATED_DATA_COMMAND, card.getCommands().get(1), select);
			Mts7ApduPayloads payloads = new Mts7ApduPayloadsFactory().createCard(exchanges);
			Mts7Card verified = new VerifyKeyPairMts7CardFactory().create(payloads);
			assertTrue(verified.isVerifiedPrivateKeyPresent(), select);
			assertEquals(10, verified.getParticipantIdentifier(), select);

			// and with the processor, which gets the application-related data before the MTB
			ApplicationRelatedDataCard processorCard = new ApplicationRelatedDataCard(ByteArrayHexStringConverter.hexStringToByteArray(select));
			Mts7Processor processor = new VerifyKeyPairMts7ProcessorFactory(executor).create();
			processor.start();
			try {
				new ProcessorMts7ApduExchangesFactory(MockRandomFactory.newInstance(participant10.getRandomValue())).create(new DefaultMts7Card(processorCard),
						processor, null);
				Mts7Card processed = processor.waitForVerify(0);
				assertTrue(processed.isVerifiedPrivateKeyPresent(), select);
				assertEquals(10, processed.getParticipantIdentifier(), select);
			} finally {
				processor.close();
			}
		}
	}

	@Test
	public void testCardWithFileManagementDataIsNotAskedForIt() throws Exception {
		// the recorded cards return it in the select application response, so the reader does not ask for it
		SimulatedCard card = new SimulatedCard(participant10, true, 1024, mtb(participant10));
		read(new DefaultMts7Card(card), random());

		for (byte[] command : card.getCommands()) {
			assertFalse(Arrays.equals(command, Mts7ApduExchangesFactory.GET_APPLICATION_RELATED_DATA_COMMAND));
		}
	}

	/**
	 * A card whose response is shorter than a status word.
	 */

	private static class ShortResponseCard extends SimulatedCard {

		public ShortResponseCard() {
			super(participant10, true, 1024, mtb(participant10));
		}

		@Override
		public byte[] transceive(byte[] command) throws IOException {
			if ((command[1] & 0xFF) == 0xCC) {
				getCommands().add(command);
				return new byte[] { (byte) 0x90 };
			}
			return super.transceive(command);
		}
	}

	@Test
	public void testResponseWithoutStatusWordIsCardProblem() throws Exception {
		// read from the card as it is, so it came from the card, which a card which is not valid can send
		assertThrows(UnexpectedCardResponseException.class, () -> read(new DefaultMts7Card(new ShortResponseCard()), random()));
		assertThrows(UnexpectedCardResponseException.class, () -> readWithProcessor(new DefaultMts7Card(new ShortResponseCard()), random()));
	}

	/**
	 * A card with a maximum response length which is less than its select application response and its signature, so that it returns them in parts, as every
	 * card may (MTS7 section 2.1). It may also ask for the exact Le of internal authenticate (6Cxx, ISO/IEC 7816-4 section 5.6).
	 */

	private static class ChainingCard extends SimulatedCard {

		private final int maximumResponseLength;
		private final boolean exactLe;

		// the rest of a response, without the status word
		private byte[] pending;
		private int offset;

		public ChainingCard(int maximumResponseLength, boolean exactLe) {
			super(participant10, true, 1024, mtb(participant10));
			this.maximumResponseLength = maximumResponseLength;
			this.exactLe = exactLe;
		}

		@Override
		public byte[] transceive(byte[] command) throws IOException {
			int ins = command[1] & 0xFF;
			if (ins == 0xA4) {
				getCommands().add(command);
				return firstPart(getResponse(participant10, 0));
			}
			if (ins == 0x88) {
				getCommands().add(command);
				byte[] response = lastResponse(participant10);
				int le = command[command.length - 1] & 0xFF;
				if (exactLe && (le == 0 ? 256 : le) != response.length - 2) {
					return new byte[] { 0x6C, (byte) (response.length - 2) };
				}
				return firstPart(response);
			}
			if (ins == 0xC0 && pending != null) {
				getCommands().add(command);
				return nextPart();
			}
			return super.transceive(command);
		}

		private byte[] firstPart(byte[] response) {
			pending = Arrays.copyOf(response, response.length - 2);
			offset = 0;
			return nextPart();
		}

		private byte[] nextPart() {
			int length = Math.min(maximumResponseLength, pending.length - offset);
			byte[] part = new byte[length + 2];
			System.arraycopy(pending, offset, part, 0, length);
			offset += length;
			int remaining = pending.length - offset;
			if (remaining > 0) {
				part[length] = 0x61;
				part[length + 1] = (byte) Math.min(remaining, 0xFF);
			} else {
				part[length] = (byte) 0x90;
				part[length + 1] = 0x00;
				pending = null;
			}
			return part;
		}
	}

	@Test
	public void testCardWhichReturnsEveryResponseInParts() throws Exception {
		for (boolean exactLe : new boolean[] { false, true }) {
			ChainingCard card = new ChainingCard(16, exactLe);
			Mts7ApduExchanges exchanges = read(new DefaultMts7Card(card), MockRandomFactory.newInstance(participant10.getRandomValue()));

			// select application in three parts, get next data, and the signature in four (after internal authenticate again with the exact Le)
			assertEquals(exactLe ? 9 : 8, card.getCommands().size());

			Mts7ApduPayloads payloads = new Mts7ApduPayloadsFactory().createCard(exchanges);
			byte[] select = getResponse(participant10, 0);
			assertArrayEquals(Arrays.copyOf(select, select.length - 2), payloads.getSelectApplicationOutput());
			Mts7Card verified = new VerifyKeyPairMts7CardFactory().create(payloads);
			assertTrue(verified.isVerifiedPrivateKeyPresent());
			assertEquals(10, verified.getParticipantIdentifier());

			// and with the processor
			ChainingCard processorCard = new ChainingCard(16, exactLe);
			Mts7Processor processor = new VerifyKeyPairMts7ProcessorFactory(executor).create();
			processor.start();
			try {
				Mts7ApduExchanges processorExchanges = new ProcessorMts7ApduExchangesFactory(MockRandomFactory.newInstance(participant10.getRandomValue()))
						.create(new DefaultMts7Card(processorCard), processor, null);
				Mts7Card processed = processor.waitForVerify(0);
				assertTrue(processed.isVerifiedPrivateKeyPresent());
				assertEquals(10, processed.getParticipantIdentifier());
				assertEquals(payloads, new Mts7ApduPayloadsFactory().createCard(processorExchanges));
			} finally {
				processor.close();
			}
		}
	}

	// a card which is not valid is to blame for that, whatever else it did

	/**
	 * A card without the application-related data in its select application response, which rejects GET DATA of it with wrong length, which it need not accept,
	 * as MTS7 has no example of it.
	 */

	private static class WrongLengthApplicationRelatedDataCard extends SimulatedCard {

		public WrongLengthApplicationRelatedDataCard(byte[] selectApplicationResponse, byte[] internalAuthenticateResponse) {
			super(selectApplicationResponse, true, 1024, mtb(participant10), internalAuthenticateResponse);
		}

		@Override
		public byte[] transceive(byte[] command) throws IOException {
			if (Arrays.equals(command, Mts7ApduExchangesFactory.GET_APPLICATION_RELATED_DATA_COMMAND)) {
				getCommands().add(command);
				return SimulatedCard.WRONG_LENGTH;
			}
			return super.transceive(command);
		}
	}

	private static byte[] clonedSignature() {
		byte[] response = lastResponse(participant10).clone();
		response[0] ^= 0x01;
		return response;
	}

	private Mts7Exception verifyWithProcessor(no.entur.abt.bob.mts7.utils.nfc.Card card) throws Exception {
		Mts7Processor processor = new VerifyKeyPairMts7ProcessorFactory(executor).create();
		processor.start();
		try {
			new ProcessorMts7ApduExchangesFactory(MockRandomFactory.newInstance(participant10.getRandomValue())).create(new DefaultMts7Card(card), processor,
					null);
			processor.waitForVerify(0);
			return null;
		} catch (Mts7Exception e) {
			return e;
		} finally {
			processor.close();
		}
	}

	@Test
	public void testCardIsToBlameBeforeTheApplicationRelatedData() throws Exception {
		byte[] empty = ByteArrayHexStringConverter.hexStringToByteArray("9000");

		// the reader reads on, and the missing application-related data is only a problem with the reader if the card is valid
		WrongLengthApplicationRelatedDataCard genuine = new WrongLengthApplicationRelatedDataCard(empty, lastResponse(participant10));
		Mts7ApduExchanges exchanges = read(new DefaultMts7Card(genuine), MockRandomFactory.newInstance(participant10.getRandomValue()));
		Mts7ApduPayloads payloads = new Mts7ApduPayloadsFactory().createCard(exchanges);
		assertThrows(InsufficientCardCommandsException.class, () -> new VerifyKeyPairMts7CardFactory().create(payloads));
		assertInstanceOf(InsufficientCardCommandsException.class,
				verifyWithProcessor(new WrongLengthApplicationRelatedDataCard(empty, lastResponse(participant10))));

		// a cloned card is to blame
		WrongLengthApplicationRelatedDataCard cloned = new WrongLengthApplicationRelatedDataCard(empty, clonedSignature());
		Mts7ApduExchanges clonedExchanges = read(new DefaultMts7Card(cloned), MockRandomFactory.newInstance(participant10.getRandomValue()));
		Mts7ApduPayloads clonedPayloads = new Mts7ApduPayloadsFactory().createCard(clonedExchanges);
		assertThrows(KeyPairInvalidCardMts7Exception.class, () -> new VerifyKeyPairMts7CardFactory().create(clonedPayloads));
		assertInstanceOf(KeyPairInvalidCardMts7Exception.class, verifyWithProcessor(new WrongLengthApplicationRelatedDataCard(empty, clonedSignature())));
	}

	@Test
	public void testPaddingBeforeTheApplicationRelatedData() throws Exception {
		// 'FF' is padding (ISO/IEC 7816-4 section 5.2.2), so the reader does not retrieve the application-related data with GET DATA
		byte[] recorded = getResponse(participant10, 0);
		byte[] padded = new byte[recorded.length + 1];
		padded[0] = (byte) 0xFF;
		System.arraycopy(recorded, 0, padded, 1, recorded.length);

		WrongLengthApplicationRelatedDataCard card = new WrongLengthApplicationRelatedDataCard(padded, lastResponse(participant10));
		Mts7ApduExchanges exchanges = read(new DefaultMts7Card(card), MockRandomFactory.newInstance(participant10.getRandomValue()));
		// select application, get next data and internal authenticate
		assertEquals(3, card.getCommands().size());

		Mts7Card verified = new VerifyKeyPairMts7CardFactory().create(new Mts7ApduPayloadsFactory().createCard(exchanges));
		assertTrue(verified.isVerifiedPrivateKeyPresent());
		assertEquals(10, verified.getParticipantIdentifier());
		assertNull(verifyWithProcessor(new WrongLengthApplicationRelatedDataCard(padded, lastResponse(participant10))));
	}

	/**
	 * A card with a malformed MTB, which stops responding at internal authenticate.
	 */

	private static class SilentCard extends SimulatedCard {

		public SilentCard(byte[] mtb) {
			super(participant10, true, 1024, mtb);
		}

		@Override
		public byte[] transceive(byte[] command) throws IOException {
			if ((command[1] & 0xFF) == 0x88) {
				getCommands().add(command);
				throw new IOException("Tag was lost");
			}
			return super.transceive(command);
		}
	}

	@Test
	public void testCardWhichStopsRespondingIsToBlameForWhatWasRead() throws Exception {
		InFlightMts7CardFactory factory = new InFlightMts7CardFactory(new VerifyKeyPairMts7ProcessorFactory(executor), random());

		// not a Mobile Ticket Bundle
		InvalidCardMts7Exception e = assertThrows(InvalidCardMts7Exception.class,
				() -> factory.create(new DefaultMts7Card(new SilentCard(new byte[] { (byte) 0xA0 })), null));
		assertInstanceOf(IOException.class, e.getSuppressed()[0]);

		// a valid MTB, so nothing shows that the card is not valid
		assertThrows(IOException.class, () -> factory.create(new DefaultMts7Card(new SilentCard(mtb(participant10))), null));
	}
}
