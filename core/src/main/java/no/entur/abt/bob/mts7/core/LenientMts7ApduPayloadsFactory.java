package no.entur.abt.bob.mts7.core;

import static no.entur.abt.bob.mts7.core.Mts7ApduPayloadsFactory.getCommandPayload;
import static no.entur.abt.bob.mts7.core.Mts7ApduPayloadsFactory.isContinue;
import static no.entur.abt.bob.mts7.core.Mts7ApduPayloadsFactory.isGetDataCommand;
import static no.entur.abt.bob.mts7.core.Mts7ApduPayloadsFactory.isGetNextDataCommand;
import static no.entur.abt.bob.mts7.core.Mts7ApduPayloadsFactory.isInternalAuthenticateCommand;
import static no.entur.abt.bob.mts7.core.Mts7ApduPayloadsFactory.isResponseCommand;
import static no.entur.abt.bob.mts7.core.Mts7ApduPayloadsFactory.isSelectApplication;
import static no.entur.abt.bob.mts7.core.Mts7ApduPayloadsFactory.isSuccess;

import java.io.ByteArrayOutputStream;
import java.util.List;

import no.entur.abt.bob.mts7.api.Mts7Exception;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchange;
import no.entur.abt.bob.mts7.simple.api.Mts7ApduExchanges;

/**
 *
 * Extracts as much info as possible, also for partial reads. Does not throw exceptions.
 *
 * Note that no info can be trusted unless all checks are completed.
 */

public class LenientMts7ApduPayloadsFactory {

	public Mts7ApduPayloads createCard(Mts7ApduExchanges mts7ApduExchanges) throws Mts7Exception {

		List<Mts7ApduExchange> exchanges = mts7ApduExchanges.getExchanges();

		Mts7ApduPayloads payloads = new Mts7ApduPayloads();
		payloads.setTagId(mts7ApduExchanges.getTagId());

		int index = 0;
		while (index < exchanges.size()) {
			Mts7ApduExchange first = exchanges.get(index);

			// iterate over continue / "response" commands
			int endIndex = index + 1; // exclusive
			while (endIndex < exchanges.size()) {
				Mts7ApduExchange previous = exchanges.get(endIndex - 1);
				Mts7ApduExchange current = exchanges.get(endIndex);

				if (!isContinue(previous.getResponse())) {
					break;
				}
				if (!isResponseCommand(current.getCommand())) {
					break;
				}
				endIndex++;
			}
			;

			Mts7ApduExchange last = exchanges.get(endIndex - 1);
			if (isSuccess(last.getResponse())) {
				// keep contents
				ByteArrayOutputStream bout = new ByteArrayOutputStream(2048);
				for (int i = index; i < endIndex; i++) {
					exchanges.get(i).writeResponsePayload(bout);
				}

				byte[] command = first.getCommand();
				if (isSelectApplication(command)) {
					payloads.setSelectApplicationOutput(bout.toByteArray());
				} else if (isInternalAuthenticateCommand(command)) {
					payloads.setInternalAuthenticateInput(getCommandPayload(first.getCommand()));
					payloads.setInternalAuthenticateOutput(bout.toByteArray());
				} else if (isGetDataCommand(command) || isGetNextDataCommand(command)) {
					payloads.setGetDataOutput(bout.toByteArray());
				}

			} else {
				// discard contents
			}

			index = endIndex;
		}

		return payloads;
	}
}
