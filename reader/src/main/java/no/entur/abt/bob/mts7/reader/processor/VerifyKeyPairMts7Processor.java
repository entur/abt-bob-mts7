package no.entur.abt.bob.mts7.reader.processor;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper;

import no.entur.abt.bob.mts7.core.Mts7Card;
import no.entur.abt.bob.mts7.core.Mts7CardEnricher;
import no.entur.abt.bob.mts7.core.UnableToConstructIccKeyException;
import no.entur.abt.bob.mts7.core.UnableToConstructThumbprintKeyException;
import no.entur.abt.bob.mts7.core.UnableToVerifyKeyPairException;
import no.entur.abt.bob.mts7.core.pki.IccPublicKey;
import no.entur.abt.bob.mts7.core.pki.IccPublicKeyFactory;
import no.entur.abt.bob.mts7.core.pki.ThumbprintFactory;
import no.entur.abt.bob.mts7.utils.ByteArrayHexStringConverter;

/**
 * 
 * Processor for MTS7 card integrity check. This only verifies that the card has the private key, not the key chain.
 * 
 */

public class VerifyKeyPairMts7Processor implements Runnable, Mts7Processor {

	private static final Logger LOGGER = LoggerFactory.getLogger(VerifyKeyPairMts7Processor.class);

	protected volatile Thread thread;
	protected volatile boolean close;

	protected final Object inputMonitor = new Object();
	protected final Object outputMonitor = new Object();

	private byte[] selectApplicationResponsePayload;
	private byte[] getDataResponsePayload;

	private byte[] internalAuthenticateResponsePayload;
	private byte[] internalAuthenticateCommandPayload;

	protected final IccPublicKeyFactory iccSignatureFactory;
	protected final CBORMapper cborMapper;
	protected final Mts7CardEnricher enricher;

	protected volatile Mts7Card result;
	protected String iccKeyAlgorithm;

	protected ThumbprintFactory thumbprintFactory;
	protected CBORExtractor algorithmExtractor;

	public VerifyKeyPairMts7Processor(IccPublicKeyFactory factory, Mts7CardEnricher enricher, CBORMapper cborMapper, ThumbprintFactory thumbprintFactory) {
		super();

		this.iccSignatureFactory = factory;

		this.cborMapper = cborMapper;
		this.enricher = enricher;
		this.thumbprintFactory = thumbprintFactory;

		this.algorithmExtractor = new CBORExtractor(cborMapper);
	}

	@Override
	public void onGetData(byte[] responsePayload) {
		synchronized (inputMonitor) {
			this.getDataResponsePayload = responsePayload;

			inputMonitor.notifyAll();
		}
	}

	@Override
	public void onSelectApplication(byte[] responsePayload) {
		synchronized (inputMonitor) {
			this.selectApplicationResponsePayload = responsePayload;

			inputMonitor.notifyAll();
		}
	}

	@Override
	public void onInternalAuthenticate(byte[] commandPayload, byte[] responsePayload) {
		synchronized (inputMonitor) {
			this.internalAuthenticateCommandPayload = commandPayload;
			this.internalAuthenticateResponsePayload = responsePayload;

			inputMonitor.notifyAll();
		}
	}

	public void start() {
		thread = new Thread(this);
		thread.start();
	}

	public void close() {
		if (thread != null) {
			synchronized (inputMonitor) {
				this.close = true;

				inputMonitor.notifyAll();
			}

			thread.interrupt();
			thread = null;
		}
	}

	public String waitForAlgorithm(long delay) throws InterruptedException {
		if (iccKeyAlgorithm == null) {
			synchronized (outputMonitor) {
				if (iccKeyAlgorithm == null) {
					outputMonitor.wait(delay);
				}
			}
		}
		return iccKeyAlgorithm;
	}

	public Mts7Card waitForVerify(long timeout) throws InterruptedException, UnableToVerifyKeyPairException {
		if (thread != null) {
			thread.join(timeout);
			thread = null;
		}

		if (!result.isVerifiedPrivateKeyPresent()) {
			throw new UnableToVerifyKeyPairException(result);
		}

		return result;
	}

	@SuppressWarnings("unchecked")
	@Override
	public void run() {
		try {
			while (!close && selectApplicationResponsePayload == null) {
				synchronized (inputMonitor) {
					if (!close && selectApplicationResponsePayload == null) {
						inputMonitor.wait();
					}
				}
			}

			if (close) {
				LOGGER.info("Closing processor");
				return;
			}

			this.result = new Mts7Card();

			enricher.enrichSelectApplicationResponsePayload(result, selectApplicationResponsePayload);

			LOGGER.info("Processed 'select application' response");

			while (!close && getDataResponsePayload == null) {
				synchronized (inputMonitor) {
					if (!close && getDataResponsePayload == null) {
						inputMonitor.wait();
					}
				}
			}

			if (close) {
				LOGGER.info("Closing processor");
				return;
			}

			Map<String, Object> otherValue = cborMapper.readValue(getDataResponsePayload, Map.class);
			byte[] p = (byte[]) otherValue.get("p");

			byte[][] cborArray = cborMapper.readValue(p, byte[][].class);

			IccPublicKey iccPublicKey = null;

			// determine which issuer key to use
			for (int i = 0; i < cborArray.length - 1; i++) {
				byte[] value = cborArray[i];

				Map<String, Object> m = cborMapper.readValue(value, Map.class);

				// To be able to distinguish between the Issuer Signature and the Device Signature (see section 2.5) header, the Issuer Signature Protected
				// Header MUST NOT contain a did parameter.
				if (m.containsKey("did")) {
					continue;
				}

				Object kidObject = m.get("kid");
				if (kidObject == null) {
					continue;
				}

				Object iidObject = m.get("iid");
				if (iidObject == null) {
					continue;
				}

				// note here what kind of algorithm we are using
				// EC and RSA do not encode the input to the internal authenticate function
				// in the same way.

				synchronized (outputMonitor) {
					this.iccKeyAlgorithm = (String) m.get("alg");

					outputMonitor.notifyAll();
				}

				try {
					iccPublicKey = iccSignatureFactory.create(m);
				} catch (UnableToConstructIccKeyException e) {
					LOGGER.info("Unable to create ICC public key", e);
				}

				try {
					result.setThumbprint(thumbprintFactory.create(m));
				} catch (UnableToConstructThumbprintKeyException e) {
					LOGGER.info("Unable to construct thumbprint", e);
				}

				break;
			}

			LOGGER.info("Processed 'get (next) data' response");

			// most of the waiting is here
			while (!close && internalAuthenticateResponsePayload == null) {
				synchronized (inputMonitor) {
					if (!close && internalAuthenticateResponsePayload == null) {
						inputMonitor.wait();
					}
				}
			}

			if (close) {
				LOGGER.info("Closing processor");

				return;
			}

			LOGGER.info(ByteArrayHexStringConverter.toHexString(internalAuthenticateResponsePayload));
			if (iccPublicKey != null && iccPublicKey.verify(internalAuthenticateCommandPayload, internalAuthenticateResponsePayload)) {
				LOGGER.info("Verified ICC private key");
				result.setVerifiedPrivateKeyPresent(true);
			} else {
				LOGGER.info("Unable to verify ICC private key");
				result.setVerifiedPrivateKeyPresent(false);
			}

			LOGGER.info("Processed 'internal authenticate' response");

		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		} catch (Exception e) {
			LOGGER.info("Problem processing files", e);
		} finally {
			// notify result waiters
			synchronized (outputMonitor) {
				outputMonitor.notifyAll();
			}
		}
	}

}
