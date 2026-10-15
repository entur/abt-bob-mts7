package no.entur.abt.bob.mts7.core;

import java.io.ByteArrayOutputStream;
import java.util.List;

import no.entur.abt.bob.mts7.api.Mts7Exception;
import no.entur.abt.bob.mts7.api.UnexpectedCardResponseException;
import no.entur.abt.bob.mts7.api.apdu.CommandAPDU;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchange;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchanges;

public class Mts7ApduPayloadsFactory {

	public Mts7ApduPayloads createCard(Mts7ApduExchanges mts7ApduExchanges) throws Mts7Exception {

		List<Mts7ApduExchange> exchanges = mts7ApduExchanges.getExchanges();

		if (exchanges.size() <= 2) {
			throw new MissingCardCommandsException();
		}

		Mts7ApduPayloads payloads = new Mts7ApduPayloads();
		payloads.setTagId(mts7ApduExchanges.getTagId());

		// first must be select application
		Mts7ApduExchange first = exchanges.get(0);

		if (!isSelectApplication(first.getCommand())) {
			throw new UnexpectedCardCommandException(first.getCommand(), first.getResponse());
		}

		if (!isSuccess(first.getResponse())) {
			throw new UnexpectedCardResponseException(first.getCommand(), first.getResponse());
		}

		payloads.setSelectApplicationOutput(getResposePayload(first.getResponse()));

		// last must be internal authenticate
		Mts7ApduExchange last = exchanges.get(exchanges.size() - 1);
		if (!isInternalAuthenticateCommand(last.getCommand())) {
			throw new UnexpectedCardCommandException(last.getCommand(), last.getResponse());
		}

		if (!isSuccess(last.getResponse())) {
			throw new UnexpectedCardResponseException(last.getCommand(), last.getResponse());
		}

		payloads.setInternalAuthenticateInput(getCommandPayload(last.getCommand()));
		payloads.setInternalAuthenticateOutput(getResposePayload(last.getResponse()));

		// the rest must be get (next) data or get response
		// possibly with an unsuccessful internal authenticate

		int apduIndex = 1;
		while (apduIndex < exchanges.size() - 1) {

			Mts7ApduExchange mts7ApduExchange = exchanges.get(apduIndex);

			byte[] command = mts7ApduExchange.getCommand();

			// there might be an intermediate authenticate which was not successful; if so then ignore it.
			if (isInternalAuthenticateCommand(command) && !isSuccess(mts7ApduExchange.getResponse())) {
				apduIndex++;

				continue;
			}

			int cla = command[0] & 0xFF;
			int ins = command[1] & 0xFF;
			int p1 = command[2] & 0xFF;
			int p2 = command[3] & 0xFF;

			if (!isGetDataCommand(cla, ins, p1, p2) && !isGetNextDataCommand(cla, ins, p1, p2)) {
				throw new UnexpectedCardCommandException(mts7ApduExchange.getCommand(), mts7ApduExchange.getResponse());
			}

			// a card which does not support extended length rejects it with wrong length; if so then the command is repeated with short length, so ignore it
			if (isWrongLength(mts7ApduExchange.getResponse())) {
				apduIndex++;

				continue;
			}

			ByteArrayOutputStream bout = new ByteArrayOutputStream(2048);

			// a get (next) data response is followed by get response commands for as long as the card says there is more (61xx)
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
			} while (true);

			// the last exchange of the chain (i.e. not whatever happens to follow it) must be success
			if (!isSuccess(lastOfChain.getResponse())) {
				throw new UnexpectedCardResponseException(lastOfChain.getCommand(), lastOfChain.getResponse());
			}

			payloads.setGetDataOutput(bout.toByteArray());
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

	protected static byte[] getCommandPayload(byte[] apdu) {
		CommandAPDU command = new CommandAPDU(apdu);
		return command.getData();
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
		return response.length > 2 && (response[response.length - 2] & 0xFF) == 0x61;
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
