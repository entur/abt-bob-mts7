package no.entur.abt.bob.mts7.test.record;

import java.io.IOException;
import java.util.List;

import no.entur.abt.bob.mts7.test.record.bob.Mts7PrettyPrintCardRecordingAnalyzer;
import no.entur.abt.bob.mts7.test.record.bob.Mts7PrettyPrinterCard;
import no.entur.tlv.utils.TlvPrettyPrinter;

public class CardRecordingPrettyPrinter {

	public static Builder newBuilder() {
		return new Builder();
	}

	public static class Builder {

		private TlvPrettyPrinter prettyPrinter;
		private boolean silent = false;

		public Builder withSilent(boolean silent) {
			this.silent = silent;
			return this;
		}

		public Builder withPrettyPrinter(TlvPrettyPrinter defaultPrettyPrinter) {
			this.prettyPrinter = defaultPrettyPrinter;
			return this;
		}

		public CardRecordingPrettyPrinter build() throws Exception {
			if (prettyPrinter == null) {
				prettyPrinter = TlvPrettyPrinter.newBuilder().build();
			}

			Mts7PrettyPrintCardRecordingAnalyzer analyzer = new Mts7PrettyPrintCardRecordingAnalyzer(prettyPrinter);

			return new CardRecordingPrettyPrinter(analyzer, silent);
		}

	}

	protected final Mts7PrettyPrintCardRecordingAnalyzer analyzer;
	protected final boolean silent;

	public CardRecordingPrettyPrinter(Mts7PrettyPrintCardRecordingAnalyzer analyzer, boolean silent) {
		this.analyzer = analyzer;
		this.silent = silent;
	}

	public void prettyPrintToStandardOut(CardRecording recording) throws IOException {
		prettyPrint(recording.toPlayback());
	}

	private void prettyPrint(CardPlayback playback) throws IOException {
		try (Mts7PrettyPrinterCard card = new Mts7PrettyPrinterCard(playback, analyzer, false)) {
			for (CardInvocation cardInvocation : playback.getInvocations()) {
				if (cardInvocation instanceof TransceiveInvocation) {
					TransceiveInvocation transceiveInvocation = (TransceiveInvocation) cardInvocation;

					card.transceive(transceiveInvocation.getCommand());
				} else if (cardInvocation instanceof CloseInvocation) {
					card.getLogger().info("Close");
				} else if (cardInvocation instanceof ConnectInvocation) {
					card.getLogger().info("Connect");
				}
			}
		} finally {
			analyzer.reset();
		}
	}

	public void prettyPrintToStandardOut(List<CardInvocation> invocations) throws IOException {
		prettyPrint(new CardPlayback(invocations));
	}

}
