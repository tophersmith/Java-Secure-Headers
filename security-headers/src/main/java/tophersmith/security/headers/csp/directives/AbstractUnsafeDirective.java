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
package tophersmith.security.headers.csp.directives;

import java.util.ArrayList;
import java.util.List;

import tophersmith.security.headers.csp.CSPValidationReport;
import tophersmith.security.headers.util.SecureRandomUtil;
import tophersmith.security.headers.util.Validator;

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
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".split("");

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
	 * @param size the string length. This value will be set to the nearest multiple of 4
	 * @return an alphanumeric string of length size 
	 */
	public static String generateNonce(int size) {
		return SecureRandomUtil.generateRandomString(AbstractUnsafeDirective.NONCE_CHARSET, size/4*4);
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
	 * @return true if val is one of 'unsafe-eval' 'unsafe-inline' or starts with 'nonce
	 */
	@Override
	protected boolean isValidKeyword(String val) {
		return super.isValidKeyword(val) || Validator.isValidUnsafeKeyword(val);
	}
	
	/**
	 * test whether this directive value contains valid hashes
	 * @param report a validation report to hold any issues discovered 
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
			int dash = hash.indexOf("-");
			int lastquote = hash.lastIndexOf("'");
			if(dash < 0 || lastquote < 0){
				report.addError(this, "Hash: " + hash + " does not have a valid value");
			}
			String hashVal = hash.substring(dash+1, lastquote);
			if(!Validator.isBase64String(hashVal)){
				report.addError(this, "Hash: " + hash + " is not base-64 encoded");
			}
		}
	}
	
	/**
	 * test whether this directive value contains valid nonces
	 * @param report a validation report to hold any issues discovered 
	 */
	protected void validateNonces(CSPValidationReport report){
		for (int j = 0; j < this.nonces.size(); j++) {
			String nonce = this.nonces.get(j);
			int dash = nonce.indexOf("-");
			int lastquote = nonce.lastIndexOf("'");
			if(dash < 0 || lastquote < 0){
				report.addError(this, "Nonce: " + nonce + " does not have a valid value");
			}
			String nonceVal = nonce.substring(dash+1, lastquote);
			if(!Validator.isBase64String(nonceVal)){
				report.addError(this, "Nonce: " + nonce + " is not base-64 encoded");
			}
		}
	}
	
	/**
	 * builds the nonce and hash values if set
	 * @return a string containing all nonces and hashes, or empty
	 */
	@Override
	protected String buildDirectiveValue() {
		StringBuilder sb = new StringBuilder();
		sb.append(getDirectiveName());
		sb.append(buildStandardDirectiveValues());
		for (int i = 0; i < this.nonces.size(); i++) {
			sb.append(this.nonces.get(i)).append(" ");
		}
		for (int i = 0; i < this.hashes.size(); i++) {
			sb.append(this.hashes.get(i)).append(" ");
		}
		return sb.toString();
	}
	
	
	/**
	 * For this Unsafe-style Directive, validate according to 
	 * {@link AbstractSrcDirective#validateAndReport(CSPValidationReport)}
	 * also validate the hashes and nonces
	 */
	@Override
	public void validateAndReport(CSPValidationReport report) {
		super.validateAndReport(report);
		validateHashes(report);
		validateNonces(report);
	}
}
