/*
 * Copyright 2015 Christopher Smith
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package topher.smith.security.headers.csp.directives;

import java.util.ArrayList;
import java.util.List;

import topher.smith.security.headers.csp.CSPValidationReport;
import topher.smith.security.headers.util.SecureRandomUtil;

/**
 * The AbstractUnsafeDirective is a base class for script-src and style-src
 * that uses the 'unsafe-inline' or 'unsafe-eval' which also use the nonce 
 * and hash source values.
 * 
 * @author Chris Smith
 *
 */
public abstract class AbstractUnsafeDirective extends AbstractSrcDirective {

	private List<String> nonces = null;
	private List<String> hashes = null;

	//character set is Alpha-Numerics
	private static final String[] NONCE_CHARSET = 
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".split("");

	protected static final String INLINE = "'unsafe-inline'";
	protected static final String EVAL = "'unsafe-eval'";

	private static final String NONCE_PREFIX = "nonce";
	private static final String QUOTE = "'";
	private static final String SEPARATOR = "-";

	private static final String[] ALLOWED_HASH_ALGO = { "sha256", "sha384", "sha512" };

	protected AbstractUnsafeDirective(String name) {
		super(name);
		this.nonces = new ArrayList<String>();
		this.hashes = new ArrayList<String>();
	}

	/**
	 * adds a hash value to this directive
	 * 
	 * @param type one of "sha256", "sha384", "sha512"
	 * @param b64hash a base64 hash value
	 */
	protected void addNewHash(String type, String b64hash) {
		if (type != null && b64hash != null) {
			String hash = new StringBuilder().append(AbstractUnsafeDirective.QUOTE).append(type)
					.append(AbstractUnsafeDirective.SEPARATOR).append(b64hash).append(AbstractUnsafeDirective.QUOTE)
					.toString();
			this.hashes.add(hash);
		}
	}

	/**
	 * removes all hashes from this directive
	 */
	public void resetHashes() {
		this.hashes.clear();
	}

	/**
	 * adds a nonce value to this directive
	 * 
	 * @param nonce a randomly generated value from {@link #generateNonce(int)}
	 */
	protected void addNewNonce(String nonce) {
		if (nonce != null) {
			String nce = new StringBuilder().append(AbstractUnsafeDirective.QUOTE)
					.append(AbstractUnsafeDirective.NONCE_PREFIX).append(AbstractUnsafeDirective.SEPARATOR)
					.append(nonce).append(AbstractUnsafeDirective.QUOTE).toString();
			this.nonces.add(nce);
		}
	}
	
	/**
	 * construct a secure alphanumeric nonce string
	 *  
	 * @param size the string length
	 * @return an alphanumeric string of length size 
	 */
	public static String generateNonce(int size) {
		return SecureRandomUtil.generateRandomString(AbstractUnsafeDirective.NONCE_CHARSET, size);
	}
	
	

	/**
	 * removes all nonces from this directive
	 */
	public void resetNonces() {
		this.nonces.clear();
	}

	/**
	 * test whether this directive value is a Keyword
	 * @param val a directive value to validate
	 * @param report a validation report to hold any issues discovered 
	 * @return true if val is one of 'unsafe-eval' 'unsafe-inline' or starts with 'nonce
	 */
	@Override
	protected boolean isValidKeyword(String val, CSPValidationReport report) {
		return val.equals(AbstractCSPDirective.SRC_UNSAFE_EVAL) || 
				val.equals(AbstractCSPDirective.SRC_UNSAFE_INLINE);
	}
	
	/**
	 * test whether this directive value is a hash
	 * @param val a directive value to validate
	 * @param report a validation report to hold any issues discovered 
	 * @return true if val starts with a valid hashtype
	 */
	protected void validateHashes(CSPValidationReport report) {
		for (int j = 0; j < this.hashes.size(); j++) {
			boolean valid = false;
			String hash = this.hashes.get(j);
			for (int i = 0; i < AbstractUnsafeDirective.ALLOWED_HASH_ALGO.length; i++) {
				if (hash.startsWith(AbstractUnsafeDirective.QUOTE + 
						AbstractUnsafeDirective.ALLOWED_HASH_ALGO[i])) {
					valid = true;
					break;
				}
			}
			if (!valid) {
				report.addError(this, "Hash algorithm " + hash + " not allowed");
			}
		}
	}
	
	/**
	 * builds the nonce and hash values if set
	 * @return a string containing all nonces and hashes, or empty
	 */
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
	
	
	@Override
	public void validateAndReport(CSPValidationReport report) {
		super.validateAndReport(report);
		validateHashes(report);
		/*
		 * nonces need not be validated as they are always of 
		 * the same form and the value can technically be any
		 * string, not just a generated one 
		 */
	}
}
