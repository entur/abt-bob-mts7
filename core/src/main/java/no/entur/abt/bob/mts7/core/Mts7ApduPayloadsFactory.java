package no.entur.abt.bob.mts7.core;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

import no.entur.abt.bob.mts7.api.InsufficientCardCommandsException;
import no.entur.abt.bob.mts7.api.InvalidCardMts7Exception;
import no.entur.abt.bob.mts7.api.MalformedCardResponseException;
import no.entur.abt.bob.mts7.api.ReaderMts7Exception;
import no.entur.abt.bob.mts7.api.UnexpectedCardResponseException;
import no.entur.abt.bob.mts7.api.apdu.CommandAPDU;
import no.entur.abt.bob.mts7.core.exception.MalformedCardCommandException;
import no.entur.abt.bob.mts7.core.exception.MissingCardCommandsException;
import no.entur.abt.bob.mts7.core.exception.UnexpectedCardCommandException;
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
	 * The length of the longest signature of a card: RSA with a modulus of 2048 bits (MTS7 section 2.1). A signature by EC with P-256 is 64 bytes.
	 */

	public static final int MAXIMUM_SIGNATURE_LENGTH = 256;

	/**
	 * The maximum number of GET RESPONSE commands for a single command, as in the readers in this library. A card which still says that there is more is to
	 * blame.
	 */

	public static final int MAXIMUM_GET_RESPONSE_COMMANDS = 256;

	/**
	 * Sort out the payloads of the exchanges with a card, as a reader following MTS7 sends them: select application first, then get (next) data, and internal
	 * authenticate last. Each command may be followed by get response for as long as the card says there is more (MTS7 section 2.1), and by the same command
	 * again if the card asks for another Le.
	 *
	 * @param mts7ApduExchanges the exchanges with the card
	 * @return the payloads. A response which is not needed to check the card at door 2 may be missing because of a problem with the reader (the select
	 *         application response, the application-related data or the signature), which is then kept in the payloads, to be reported once the card has been
	 *         checked as far as it can be (see {@linkplain Mts7ApduPayloads#getReaderProblem()})
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

		List<Chain> chains = toChains(exchanges);

		// first must be select application of the travel card application. The command is checked before the response, as the card can only answer the
		// command it got.
		Chain first = chains.get(0);

		byte[] select = first.getCommand();
		if (!isSelectApplication(select)) {
			throw new UnexpectedCardCommandException(select, first.getHead().getResponse());
		}
		byte[] applicationIdentifier = getCommandPayload(select);
		if (!startsWith(applicationIdentifier, APPLICATION_IDENTIFIER)) {
			// another application (MTS7 section 3.1.1)
			throw new UnexpectedCardCommandException(select, first.getHead().getResponse());
		}
		InsufficientCardCommandsException selectProblem = checkChain(first);
		if (selectProblem != null && !isContinue(first.getLast().getResponse())) {
			// the card did not execute select application, which everything else depends on
			throw selectProblem;
		}

		if (selectProblem != null) {
			// The card has selected the application, but the rest of its response is missing. Only the application-related data is needed from it, which
			// the reader may also have retrieved with GET DATA.
			deferReaderProblem(payloads, selectProblem);
		} else if (!isSuccess(first.getLast().getResponse())) {
			if (applicationIdentifier.length != APPLICATION_IDENTIFIER.length) {
				// only the RID and the application are submitted (MTS7 section 4.1.1), and the card need not have an application by a longer name
				throw new MalformedCardCommandException("Select application of an application identifier of " + applicationIdentifier.length + " bytes, not "
						+ APPLICATION_IDENTIFIER.length + ", which the card rejected with status word " + toStatusWord(first.getLast().getResponse()));
			}
			throw new UnexpectedCardResponseException(first.getLast().getCommand(), first.getLast().getResponse());
		} else {
			// may be empty (MTS7 section 4.1.1), then the application-related data is retrieved with GET DATA
			payloads.setSelectApplicationOutput(first.getResponsePayload());
		}

		// last must be internal authenticate
		Chain last = chains.get(chains.size() - 1);
		if (!isInternalAuthenticateCommand(last.getCommand())) {
			throw new UnexpectedCardCommandException(last.getCommand(), last.getHead().getResponse());
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
		InsufficientCardCommandsException internalAuthenticateProblem = checkChain(last);

		payloads.setInternalAuthenticateInput(challenge);
		if (internalAuthenticateProblem != null) {
			// the signature is missing, but the card can still be checked at door 2
			deferReaderProblem(payloads, internalAuthenticateProblem);
		} else if (!isSuccess(last.getLast().getResponse())) {
			if (internalAuthenticate.getNe() < MAXIMUM_SIGNATURE_LENGTH && !last.isHeadSentAsAskedFor()) {
				// the card may not be able to return its signature within Le, unless it asked for that Le
				throw new MalformedCardCommandException(
						"Internal authenticate with Le for " + internalAuthenticate.getNe() + " bytes, less than the " + MAXIMUM_SIGNATURE_LENGTH
								+ " of a signature by RSA, which the card rejected with status word " + toStatusWord(last.getLast().getResponse()));
			}
			throw new UnexpectedCardResponseException(last.getLast().getCommand(), last.getLast().getResponse());
		} else {
			payloads.setInternalAuthenticateOutput(last.getResponsePayload());
		}

		// The rest must be GET (NEXT) DATA of the MTBs (7F21) or GET DATA of the application-related data (6E), possibly with an unsuccessful internal
		// authenticate in between.

		for (int i = 1; i < chains.size() - 1; i++) {
			Chain chain = chains.get(i);

			byte[] command = chain.getCommand();

			// there might be an intermediate authenticate which was not successful; if so then ignore it.
			if (isInternalAuthenticateCommand(command) && !isSuccess(chain.getLast().getResponse())) {
				continue;
			}

			boolean mobileTicketBundle = isGetDataCommand(command) || isGetNextDataCommand(command);
			if (!mobileTicketBundle && !isGetApplicationRelatedDataCommand(command)) {
				throw new UnexpectedCardCommandException(command, chain.getHead().getResponse());
			}
			checkGetCommand(command);
			InsufficientCardCommandsException problem = checkChain(chain);
			if (problem != null) {
				if (mobileTicketBundle) {
					// without the MTB, there is nothing to check the card with
					throw problem;
				}
				// the application-related data is not needed to check the card
				deferReaderProblem(payloads, problem);
				continue;
			}

			// the last exchange of the chain (i.e. not whatever happens to follow it) must be success
			byte[] response = chain.getLast().getResponse();
			if (mobileTicketBundle && payloads.hasGetDataOutput() && isReferencedDataNotFound(response)) {
				// there is no next MTB (MTS7 section 4.1.2), as when the reader looks for more than the first
				continue;
			}
			if (!isSuccess(response)) {
				throw new UnexpectedCardResponseException(chain.getLast().getCommand(), response);
			}

			if (mobileTicketBundle) {
				// the first MTB, whose public key the card is authenticated with (MTS7 appendix A)
				if (!payloads.hasGetDataOutput()) {
					payloads.setGetDataOutput(chain.getResponsePayload());
				}
			} else {
				payloads.setApplicationRelatedDataOutput(chain.getResponsePayload());
			}
		}

		if (payloads.getGetDataOutput() == null) {
			throw new MissingCardCommandsException();
		}

		return payloads;
	}

	/**
	 * A command and what follows it for the same response: the same command again, for as long as the card asks for another Le, and GET RESPONSE for as long as
	 * the card says that there is more.
	 */

	protected static final class Chain {

		private final List<Mts7ApduExchange> exchanges = new ArrayList<>();

		// the command which the response is to: the last of the same command sent again
		private int head;

		public Chain(Mts7ApduExchange first) {
			exchanges.add(first);
		}

		public void add(Mts7ApduExchange exchange, boolean again) {
			if (again && head == exchanges.size() - 1) {
				head = exchanges.size();
			}
			exchanges.add(exchange);
		}

		public Mts7ApduExchange getHead() {
			return exchanges.get(head);
		}

		public byte[] getCommand() {
			return getHead().getCommand();
		}

		/**
		 * @param index the index of an exchange in the chain
		 * @return whether its command was sent again with the exact Le which the card asked for (6Cxx) in the response before it
		 */

		public boolean isSentAsAskedFor(int index) {
			if (index == 0) {
				return false;
			}
			byte[] response = exchanges.get(index - 1).getResponse();
			if (response.length != 2 || (response[0] & 0xFF) != 0x6C) {
				return false;
			}
			int asked = (response[1] & 0xFF) == 0 ? 256 : response[1] & 0xFF;
			try {
				return new CommandAPDU(exchanges.get(index).getCommand()).getNe() == asked;
			} catch (RuntimeException e) {
				// a malformed command, which is the fault of the reader anyway
				return false;
			}
		}

		/**
		 * @return whether the command which the response is to was sent again with the exact Le which the card asked for (6Cxx)
		 */

		public boolean isHeadSentAsAskedFor() {
			return isSentAsAskedFor(head);
		}

		public Mts7ApduExchange getLast() {
			return exchanges.get(exchanges.size() - 1);
		}

		public List<Mts7ApduExchange> getExchanges() {
			return exchanges;
		}

		/**
		 * @return the payloads of the responses, from the head on, without the status words
		 */

		public byte[] getResponsePayload() {
			ByteArrayOutputStream bout = new ByteArrayOutputStream(2048);
			for (int i = head; i < exchanges.size(); i++) {
				exchanges.get(i).writeResponsePayload(bout);
			}
			return bout.toByteArray();
		}
	}

	/**
	 * Split the exchanges into chains: each command with the same command again for as long as the card asks for another Le, and the GET RESPONSE commands for
	 * as long as the card says that there is more.
	 *
	 * @param exchanges the exchanges, which have been checked to be complete
	 * @return the chains
	 */

	protected static List<Chain> toChains(List<Mts7ApduExchange> exchanges) {
		List<Chain> chains = new ArrayList<>();
		int index = 0;
		while (index < exchanges.size()) {
			Chain chain = new Chain(exchanges.get(index++));
			while (index < exchanges.size()) {
				Mts7ApduExchange previous = chain.getLast();
				Mts7ApduExchange next = exchanges.get(index);
				if (isContinue(previous.getResponse()) && isResponseCommand(next.getCommand())) {
					// the rest of the response (MTS7 section 2.1)
					chain.add(next, false);
				} else if (isAgain(previous.getCommand(), previous.getResponse()) && isSameCommand(previous.getCommand(), next.getCommand())) {
					chain.add(next, true);
				} else {
					break;
				}
				index++;
			}
			chains.add(chain);
		}
		return chains;
	}

	/**
	 * Check a chain: its GET RESPONSE commands are as MTS7 specifies them, and the reader retrieved all of the response.
	 *
	 * @param chain the chain
	 * @return the problem with the reader if it did not retrieve all of the response: no GET RESPONSE after 61xx, or the command not sent again with other
	 *         lengths when the card asked for it; null if it did
	 * @throws MalformedCardCommandException   if a GET RESPONSE command is not as MTS7 specifies it (a problem with the reader)
	 * @throws UnexpectedCardResponseException if the card still says that there is more after {@value #MAXIMUM_GET_RESPONSE_COMMANDS} GET RESPONSE commands, or
	 *                                         asks for other lengths although it was sent the Le which it asked for (a problem on the card side)
	 */

	protected static InsufficientCardCommandsException checkChain(Chain chain) throws MalformedCardCommandException, UnexpectedCardResponseException {
		int getResponseCommands = 0;
		for (Mts7ApduExchange exchange : chain.getExchanges()) {
			if (isResponseCommand(exchange.getCommand())) {
				checkGetCommand(exchange.getCommand());
				getResponseCommands++;
			}
		}
		Mts7ApduExchange last = chain.getLast();
		if (isContinue(last.getResponse())) {
			if (getResponseCommands >= MAXIMUM_GET_RESPONSE_COMMANDS) {
				// a card which keeps saying that there is more must not keep the reader busy forever, as the readers in this library also stop
				throw new UnexpectedCardResponseException(last.getCommand(), last.getResponse());
			}
			// the card has more, but the reader did not retrieve it
			return new InsufficientCardCommandsException(last.getCommand(), last.getResponse());
		}
		if (isAgain(last.getCommand(), last.getResponse())) {
			if (chain.isSentAsAskedFor(chain.getExchanges().size() - 1)) {
				// the card asks again, although it was sent the Le which it asked for
				throw new UnexpectedCardResponseException(last.getCommand(), last.getResponse());
			}
			return new InsufficientCardCommandsException(
					"Command not sent again with other lengths, which the card asked for with status word " + toStatusWord(last.getResponse()),
					last.getCommand(), last.getResponse());
		}
		return null;
	}

	/**
	 * Keep a problem with the reader to report once the card has been checked as far as it can be (see {@linkplain Mts7ApduPayloads#getReaderProblem()}). The
	 * first one is kept.
	 */

	protected static void deferReaderProblem(Mts7ApduPayloads payloads, ReaderMts7Exception problem) {
		if (!payloads.hasReaderProblem()) {
			payloads.setReaderProblem(problem);
		}
	}

	/**
	 * Whether the card asks for a command again with another Le: wrong Le, with the exact length in SW2 (6Cxx, ISO/IEC 7816-4 section 5.6), or wrong length
	 * (6700) to a command with other lengths than in an example in MTS7 which every card must accept (see {@linkplain #hasExampleLengths(byte[])}).
	 *
	 * @param command  the command
	 * @param response the response to it
	 * @return true if the card did not execute the command, and the reader is to send it again with other lengths
	 */

	protected static boolean isAgain(byte[] command, byte[] response) {
		if (response.length != 2) {
			return false;
		}
		if ((response[0] & 0xFF) == 0x6C) {
			return true;
		}
		return isWrongLength(response) && !hasExampleLengths(command);
	}

	/**
	 * Whether a command has the lengths of an example in MTS7 which every card must accept, so that the card is to blame for rejecting them with wrong length
	 * (6700): select application with a short Le of 00 (section 4.1.1) or without Le (appendix A), and internal authenticate with a short Le of 00 (section
	 * 4.1.4). The examples of GET (NEXT) DATA and GET RESPONSE have an extended Le, which the card need not support (section 3.1.4), and there is no example of
	 * GET DATA of the application-related data.
	 *
	 * @param command the command
	 * @return true if the card must accept the lengths of the command
	 */

	protected static boolean hasExampleLengths(byte[] command) {
		if (isExtendedLength(command)) {
			return false;
		}
		CommandAPDU apdu;
		try {
			apdu = new CommandAPDU(command);
		} catch (RuntimeException e) {
			// a malformed command, which is the fault of the reader anyway
			return false;
		}
		if (isSelectApplication(command)) {
			return apdu.getNe() == 256 || apdu.getNe() == 0;
		}
		if (isInternalAuthenticateCommand(command)) {
			return apdu.getNe() == 256;
		}
		return false;
	}

	/**
	 * An extended length has a zero byte where a short length has its Lc or Le (ISO/IEC 7816-4 section 5.1), except for a short Le of 00 at the end of the
	 * command.
	 *
	 * @param command the command
	 * @return true if the command has an extended length
	 */

	protected static boolean isExtendedLength(byte[] command) {
		return command.length > 5 && command[4] == 0x00;
	}

	/**
	 * Whether a command is the same as another one, apart from its lengths: the same header, or GET DATA and GET NEXT DATA of an MTB.
	 */

	protected static boolean isSameCommand(byte[] command, byte[] other) {
		if ((isGetDataCommand(command) || isGetNextDataCommand(command)) && (isGetDataCommand(other) || isGetNextDataCommand(other))) {
			return true;
		}
		return command[0] == other[0] && command[1] == other[1] && command[2] == other[2] && command[3] == other[3];
	}

	protected static String toStatusWord(byte[] response) {
		return String.format("%02X%02X", response[response.length - 2] & 0xFF, response[response.length - 1] & 0xFF);
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
