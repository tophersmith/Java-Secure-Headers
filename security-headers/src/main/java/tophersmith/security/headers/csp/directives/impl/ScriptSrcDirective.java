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
package tophersmith.security.headers.csp.directives.impl;

import tophersmith.security.headers.csp.directives.AbstractUnsafeDirective;
import tophersmith.security.headers.util.Validator;

/**
 * From 
 * <a href="https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet">
 * https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet</a>}
 * <br>
 * The script-src directive restricts which scripts the protected resource 
 * can execute. Additional restrictions against inline scripts, and eval. 
 * Additional directives were added in CSP2 for hash and nonce support. 
 * This directive relies on the CSP default-src list if this directive 
 * is undefined. See 
 * <a href="http://www.w3.org/TR/CSP2/#directive-base-uri">
 * http://www.w3.org/TR/CSP2/#directive-base-uri</a>
 * 
 * @author Chris Smith
 *
 */
public class ScriptSrcDirective extends AbstractUnsafeDirective {

	/**
	 * The name of the directive
	 */
	public static final String NAME = "script-src";

	public ScriptSrcDirective() {
		super(ScriptSrcDirective.NAME);
	}

	/**
	 * adds the value 'none' to the directive
	 * @return a reference to this object
	 */
	public ScriptSrcDirective addNone() {
		addDirectiveValue(Validator.SRC_KEY_NONE);
		return this;
	}

	/**
	 * adds the value 'self' to the directive
	 * @return a reference to this object
	 */
	public ScriptSrcDirective addSelf() {
		addDirectiveValue(Validator.SRC_KEY_SELF);
		return this;
	}

	/**
	 * adds the given value to the directive
	 * @param source the src-list attribute to add to the directive
	 * @return a reference to this object
	 */
	public ScriptSrcDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}

	/**
	 * adds the value 'unsafe-inline' to the directive
	 * @return a reference to this object
	 */
	public ScriptSrcDirective addUnsafeInline() {
		addDirectiveValue(Validator.SRC_UNSAFE_INLINE);
		return this;
	}

	/**
	 * adds the value 'unsafe-eval' to the directive
	 * @return a reference to this object
	 */
	public ScriptSrcDirective addUnsafeEval() {
		addDirectiveValue(Validator.SRC_UNSAFE_EVAL);
		return this;
	}

	/**
	 * adds the value 'nonce-${nonce}' to the directive
	 * @param nonce the nonce value taken from {@link #generateNonce(int)}
	 * @return a reference to this object
	 */
	public ScriptSrcDirective addNonce(String nonce) {
		addNewNonce(nonce);
		return this;
	}

	/**
	 * adds the value '${hashType}-${b64Hash}' to the directive
	 * @param hashType one of "sha256", "sha384", or "sha512"
	 * @param b64Hash a base-64 encoded hash of a script
	 * @return a reference to this object
	 */
	public ScriptSrcDirective addHash(String hashType, String b64Hash) {
		addNewHash(hashType, b64Hash);
		return this;
	}
}
