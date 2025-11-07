package no.entur.abt.bob.mts7.simple.api;

import java.util.ArrayList;
import java.util.List;

public class Mts7ApduExchanges {

	private byte[] tagId;

	private List<Mts7ApduExchange> exchanges = new ArrayList<>();

	public boolean add(Mts7ApduExchange e) {
		return exchanges.add(e);
	}

	public void setExchanges(List<Mts7ApduExchange> invocations) {
		this.exchanges = invocations;
	}

	public List<Mts7ApduExchange> getExchanges() {
		return exchanges;
	}

	public void setTagId(byte[] tagId) {
		this.tagId = tagId;
	}

	public byte[] getTagId() {
		return tagId;
	}

	public void add(byte[] command, byte[] response) {
		add(new Mts7ApduExchange(command, response));
	}
}
