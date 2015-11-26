package securityheaders.csp.directives;

import java.util.ArrayList;
import java.util.List;

import securityheaders.csp.CSPValidationReport;
import securityheaders.util.SecureRandomUtil;

public abstract class AbstractInlineDirective extends AbstractSrcDirective {

	private List<String> nonces = null;
	private List<String> hashes = null;

	private static final String[] NONCE_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
			.split("");

	protected static final String INLINE = "'unsafe-inline'";
	protected static final String EVAL = "'unsafe-eval'";

	private static final String NONCE_PREFIX = "nonce";
	private static final String QUOTE = "'";
	private static final String SEPARATOR = "-";

	private static final String[] ALLOWED_HASH_ALGO = { "sha256", "sha384", "sha512" };

	protected AbstractInlineDirective(String name) {
		super(name);
		this.nonces = new ArrayList<String>();
		this.hashes = new ArrayList<String>();
	}

	protected void addNewHash(String type, String b64hash) {
		if (type != null && b64hash != null) {
			String hash = new StringBuilder().append(AbstractInlineDirective.QUOTE).append(type)
					.append(AbstractInlineDirective.SEPARATOR).append(b64hash).append(AbstractInlineDirective.QUOTE)
					.toString();
			this.hashes.add(hash);
		}
	}

	public void resetHashes() {
		this.hashes.clear();
	}

	protected void addNewNonce(String nonce) {
		if (nonce != null) {
			String nce = new StringBuilder().append(AbstractInlineDirective.QUOTE)
					.append(AbstractInlineDirective.NONCE_PREFIX).append(AbstractInlineDirective.SEPARATOR)
					.append(nonce).append(AbstractInlineDirective.QUOTE).toString();
			this.nonces.add(nce);
		}
	}

	public static String generateNonce(int size) {
		return SecureRandomUtil.generateRandomString(AbstractInlineDirective.NONCE_CHARSET, size);
	}

	public void resetNonces() {
		this.nonces.clear();
	}

	@Override
	protected boolean isValidKeyword(String val) {
		return val.equals(AbstractCSPDirective.SRC_UNSAFE_EVAL) || val.equals(AbstractCSPDirective.SRC_UNSAFE_INLINE)
				|| val.startsWith(AbstractInlineDirective.NONCE_PREFIX);
	}

	@Override
	protected void validateAdditional(CSPValidationReport report) {
		for (int j = 0; j < this.hashes.size(); j++) {
			boolean valid = false;
			String val = this.hashes.get(j);
			for (int i = 0; i < AbstractInlineDirective.ALLOWED_HASH_ALGO.length; i++) {
				if (val.startsWith(AbstractInlineDirective.ALLOWED_HASH_ALGO[i])) {
					valid = true;
					break;
				}
			}
			if (!valid) {
				report.addReport(this, "Hash algorithm " + val + " not allowed");
			}
		}
	}

	@Override
	protected String buildCustomDirective() {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < this.nonces.size(); i++) {
			sb.append(this.nonces.get(i)).append(" ");
		}
		for (int i = 0; i < this.hashes.size(); i++) {
			sb.append(this.hashes.get(i)).append(" ");
		}
		return sb.toString();
	}
}
