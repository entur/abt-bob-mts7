package no.entur.abt.bob.mts7.core;

import java.io.ByteArrayOutputStream;
import java.util.List;

import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.api.MalformedCardResponseException;
import no.entur.abt.bob.mts7.api.ReaderMts7Exception;
import no.entur.abt.bob.mts7.api.UnexpectedCardResponseException;
import no.entur.abt.bob.mts7.api.apdu.CommandAPDU;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchange;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchanges;

/**
 * Sorts out the payloads of the exchanges with a card, which the reader (for example the control client) sends us.
 * <p>
 * Instances are thread safe.
 */

public class Mts7ApduPayloadsFactory {

	/**
	 * The length of the challenge for internal authenticate: a SHA-256 hash (MTS7, section 4.1.4)
	 */

	public static final int CHALLENGE_LENGTH = 32;

	/**
	 * The part of the application identifier which is selected: the RID and the application (MTS7 section 4.1.1)
	 */

	protected static final byte[] APPLICATION_IDENTIFIER = { (byte) 0xA0, 0x00, 0x00, 0x07, (byte) 0x81, 0x01 };

	/**
	 * Sort out the payloads of the exchanges with a card, as a reader following MTS7 sends them: select application first, then get (next) data (followed by
	 * get response for as long as the card says there is more), and internal authenticate last.
	 *
	 * @param mts7ApduExchanges the exchanges with the card
	 * @return the payloads
	 * @throws ReaderMts7Exception      if the exchanges are not as a reader following MTS7 sends them (a problem with the reader): commands are missing
	 *                                  ({@linkplain MissingCardCommandsException}), too few to retrieve all of a response
	 *                                  ({@linkplain InsufficientCardCommandsException}), unexpected ({@linkplain UnexpectedCardCommandException}), or malformed
	 *                                  ({@linkplain MalformedCardCommandException}, {@linkplain MalformedCardResponseException})
	 * @throws InvalidCardMts7Exception if the card did not respond with success ({@linkplain UnexpectedCardResponseException}, a problem on the card side)
	 */

	public Mts7ApduPayloads createCard(Mts7ApduExchanges mts7ApduExchanges) throws ReaderMts7Exception, InvalidCardMts7Exception {

		List<Mts7ApduExchange> exchanges = mts7ApduExchanges == null ? null : mts7ApduExchanges.getExchanges();

		if (exchanges == null || exchanges.size() <= 2) {
			throw new MissingCardCommandsException();
		}
		for (Mts7ApduExchange exchange : exchanges) {
			checkExchange(exchange);
		}

		Mts7ApduPayloads payloads = new Mts7ApduPayloads();
		payloads.setTagId(mts7ApduExchanges.getTagId());

		// first must be select application of the travel card application. The command is checked before the response, as the card can only answer the
		// command it got.
		Mts7ApduExchange first = exchanges.get(0);

		if (!isSelectApplication(first.getCommand())) {
			throw new UnexpectedCardCommandException(first.getCommand(), first.getResponse());
		}
		byte[] applicationIdentifier = getCommandPayload(first.getCommand());
		if (!startsWith(applicationIdentifier, APPLICATION_IDENTIFIER)) {
			// another application (MTS7 section 3.1.1)
			throw new UnexpectedCardCommandException(first.getCommand(), first.getResponse());
		}

		if (!isSuccess(first.getResponse())) {
			throw new UnexpectedCardResponseException(first.getCommand(), first.getResponse());
		}

		// may be empty (MTS7 section 4.1.1), then the application-related data is retrieved with GET DATA
		payloads.setSelectApplicationOutput(getResposePayload(first.getResponse()));

		// last must be internal authenticate
		Mts7ApduExchange last = exchanges.get(exchanges.size() - 1);
		if (!isInternalAuthenticateCommand(last.getCommand())) {
			throw new UnexpectedCardCommandException(last.getCommand(), last.getResponse());
		}

		// the challenge SHALL be a SHA-256 hash (MTS7, section 4.1.4), and the signature is only returned if asked for (Le). Checked before the response, as
		// a card may well reject another command.
		CommandAPDU internalAuthenticate = parseCommand(last.getCommand());
		byte[] challenge = internalAuthenticate.getData();
		if (challenge.length != CHALLENGE_LENGTH) {
			throw new MalformedCardCommandException("Challenge for internal authenticate of " + challenge.length + " bytes, not " + CHALLENGE_LENGTH);
		}
		if (internalAuthenticate.getNe() == 0) {
			throw new MalformedCardCommandException("Internal authenticate without Le, so it does not ask for the signature");
		}

		if (!isSuccess(last.getResponse())) {
			throw new UnexpectedCardResponseException(last.getCommand(), last.getResponse());
		}

		payloads.setInternalAuthenticateInput(challenge);
		payloads.setInternalAuthenticateOutput(getResposePayload(last.getResponse()));

		// The rest must be GET (NEXT) DATA of the MTBs (7F21) or GET DATA of the application-related data (6E), each followed by GET RESPONSE for as long as
		// the card says there is more, possibly with an unsuccessful internal authenticate in between.

		int apduIndex = 1;
		while (apduIndex < exchanges.size() - 1) {

			Mts7ApduExchange mts7ApduExchange = exchanges.get(apduIndex);

			byte[] command = mts7ApduExchange.getCommand();

			// there might be an intermediate authenticate which was not successful; if so then ignore it.
			if (isInternalAuthenticateCommand(command) && !isSuccess(mts7ApduExchange.getResponse())) {
				apduIndex++;

				continue;
			}

			boolean mobileTicketBundle = isGetDataCommand(command) || isGetNextDataCommand(command);
			if (!mobileTicketBundle && !isGetApplicationRelatedDataCommand(command)) {
				throw new UnexpectedCardCommandException(mts7ApduExchange.getCommand(), mts7ApduExchange.getResponse());
			}
			checkGetCommand(command);

			// a card which does not support extended length rejects it with wrong length; if so then the command is repeated with short length, so ignore it
			if (isWrongLength(mts7ApduExchange.getResponse())) {
				apduIndex++;

				continue;
			}

			ByteArrayOutputStream bout = new ByteArrayOutputStream(2048);

			// the response is followed by get response commands for as long as the card says there is more (61xx)
			Mts7ApduExchange lastOfChain;
			do {
				mts7ApduExchange.writeResponsePayload(bout);

				lastOfChain = mts7ApduExchange;

				apduIndex++;
				if (apduIndex >= exchanges.size() - 1) {
					break;
				}

				if (!isContinue(lastOfChain.getResponse())) {
					break;
				}

				mts7ApduExchange = exchanges.get(apduIndex);

				if (!isResponseCommand(mts7ApduExchange.getCommand())) {
					break;
				}
				checkGetCommand(mts7ApduExchange.getCommand());
			} while (true);

			// the last exchange of the chain (i.e. not whatever happens to follow it) must be success
			if (isContinue(lastOfChain.getResponse())) {
				// the card has more, but the reader did not retrieve it
				throw new InsufficientCardCommandsException(lastOfChain.getCommand(), lastOfChain.getResponse());
			}
			if (mobileTicketBundle && payloads.hasGetDataOutput() && isReferencedDataNotFound(lastOfChain.getResponse())) {
				// there is no next MTB (MTS7 section 4.1.2), as when the reader looks for more than the first
				continue;
			}
			if (!isSuccess(lastOfChain.getResponse())) {
				throw new UnexpectedCardResponseException(lastOfChain.getCommand(), lastOfChain.getResponse());
			}

			if (mobileTicketBundle) {
				// the first MTB, whose public key the card is authenticated with (MTS7 appendix A)
				if (!payloads.hasGetDataOutput()) {
					payloads.setGetDataOutput(bout.toByteArray());
				}
			} else {
				payloads.setApplicationRelatedDataOutput(bout.toByteArray());
			}
		}

		if (payloads.getGetDataOutput() == null) {
			throw new MissingCardCommandsException();
		}

		return payloads;
	}

	protected static byte[] getResposePayload(byte[] apdu) {
		byte[] payload = new byte[apdu.length - 2];
		System.arraycopy(apdu, 0, payload, 0, payload.length);
		return payload;
	}

	protected static byte[] getCommandPayload(byte[] apdu) throws MalformedCardCommandException {
		return parseCommand(apdu).getData();
	}

	protected static CommandAPDU parseCommand(byte[] apdu) throws MalformedCardCommandException {
		try {
			return new CommandAPDU(apdu);
		} catch (RuntimeException e) {
			throw new MalformedCardCommandException("Malformed command", e);
		}
	}

	/**
	 * Check a command which gets data from the card (GET DATA, GET NEXT DATA or GET RESPONSE): it has no data, and asks for the response (Le), or the card
	 * would rightly return nothing.
	 *
	 * @param apdu the command
	 * @throws MalformedCardCommandException if the command is not like that (a problem with the reader)
	 */

	protected static void checkGetCommand(byte[] apdu) throws MalformedCardCommandException {
		CommandAPDU command = parseCommand(apdu);
		if (command.getNc() != 0) {
			throw new MalformedCardCommandException("Unexpected data in a command which gets data from the card");
		}
		if (command.getNe() == 0) {
			throw new MalformedCardCommandException("Command which gets data from the card without Le");
		}
	}

	private static boolean startsWith(byte[] data, byte[] prefix) {
		if (data.length < prefix.length) {
			return false;
		}
		for (int i = 0; i < prefix.length; i++) {
			if (data[i] != prefix[i]) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Check that an exchange can be from a card: a command has at least the four bytes of its header, and a response at least the two bytes of its status word.
	 *
	 * @param exchange the exchange
	 * @throws ReaderMts7Exception if the exchange cannot be from a card (a problem with the reader): it is missing ({@linkplain MissingCardCommandsException}),
	 *                             or its command ({@linkplain MalformedCardCommandException}) or response ({@linkplain MalformedCardResponseException}) is
	 */

	protected static void checkExchange(Mts7ApduExchange exchange) throws ReaderMts7Exception {
		if (exchange == null) {
			throw new MissingCardCommandsException("Missing exchange");
		}
		byte[] command = exchange.getCommand();
		if (command == null || command.length < 4) {
			throw new MalformedCardCommandException("Malformed command: " + (command == null ? "missing" : command.length + " bytes"));
		}
		byte[] response = exchange.getResponse();
		if (response == null || response.length < 2) {
			throw new MalformedCardResponseException("Malformed response: " + (response == null ? "missing" : response.length + " bytes"));
		}
	}

	protected static boolean isSelectApplication(byte[] command) {
		int cla = command[0] & 0xFF;
		int ins = command[1] & 0xFF;
		int p1 = command[2] & 0xFF;
		int p2 = command[3] & 0xFF;

		return cla == 0x00 && ins == 0xA4 && p1 == 0x04 && p2 == 0x00;
	}

	protected static boolean isSelectApplication(int cla, int ins, int p1, int p2) {
		return cla == 0x00 && ins == 0xA4 && p1 == 0x04 && p2 == 0x00;
	}

	protected static boolean isGetDataCommand(int cla, int ins, int p1, int p2) {
		return cla == 0x00 && ins == 0xCA && p1 == 0x7F && p2 == 0x21;
	}

	protected static boolean isGetNextDataCommand(int cla, int ins, int p1, int p2) {
		return cla == 0x00 && ins == 0xCC && p1 == 0x7F && p2 == 0x21;
	}

	protected static boolean isResponseCommand(byte[] command) {
		int cla = command[0] & 0xFF;
		int ins = command[1] & 0xFF;
		int p1 = command[2] & 0xFF;
		int p2 = command[3] & 0xFF;

		return cla == 0x00 && ins == 0xC0 && p1 == 0x00 && p2 == 0x00;
	}

	protected static boolean isResponseCommand(int cla, int ins, int p1, int p2) {
		return cla == 0x00 && ins == 0xC0 && p1 == 0x00 && p2 == 0x00;
	}

	protected static boolean isInternalAuthenticateCommand(byte[] command) {
		int cla = command[0] & 0xFF;
		int ins = command[1] & 0xFF;
		int p1 = command[2] & 0xFF;
		int p2 = command[3] & 0xFF;

		return cla == 0x00 && ins == 0x88 && p1 == 0x00 && p2 == 0x00;
	}

	protected static boolean isInternalAuthenticateCommand(int cla, int ins, int p1, int p2) {
		return cla == 0x00 && ins == 0x88 && p1 == 0x00 && p2 == 0x00;
	}

	protected static boolean isContinue(byte[] response) {
		// with or without data in this part of the response
		return response.length >= 2 && (response[response.length - 2] & 0xFF) == 0x61;
	}

	protected static boolean isReferencedDataNotFound(byte[] response) {
		return response.length == 2 && (response[0] & 0xFF) == 0x6A && (response[1] & 0xFF) == 0x88;
	}

	protected static boolean isGetApplicationRelatedDataCommand(byte[] command) {
		int cla = command[0] & 0xFF;
		int ins = command[1] & 0xFF;
		int p1 = command[2] & 0xFF;
		int p2 = command[3] & 0xFF;

		return cla == 0x00 && ins == 0xCA && p1 == 0x00 && p2 == 0x6E;
	}

	protected static boolean isWrongLength(byte[] response) {
		return response.length == 2 && (response[0] & 0xFF) == 0x67 && response[1] == 0x00;
	}

	public static boolean isSuccess(byte[] response) {
		return response.length >= 2 && (response[response.length - 2] & 0xFF) == 0x90 && (response[response.length - 1] & 0xFF) == 0x00;
	}

	protected static boolean isGetDataCommand(byte[] command) {
		int cla = command[0] & 0xFF;
		int ins = command[1] & 0xFF;
		int p1 = command[2] & 0xFF;
		int p2 = command[3] & 0xFF;

		return isGetDataCommand(cla, ins, p1, p2);
	}

	protected static boolean isGetNextDataCommand(byte[] command) {
		int cla = command[0] & 0xFF;
		int ins = command[1] & 0xFF;
		int p1 = command[2] & 0xFF;
		int p2 = command[3] & 0xFF;

		return isGetNextDataCommand(cla, ins, p1, p2);
	}

}
