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
package topher.smith.security.headers.csp.directives.impl;

import topher.smith.security.headers.csp.directives.AbstractCSPDirective;
import topher.smith.security.headers.csp.directives.AbstractUnsafeDirective;

/**
 * From 
 * {@link https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet}
 * <br/>
 * The script-src directive restricts which styles the user may applies to 
 * the protected resource. Additional restrictions against inline and eval.
 * This directive relies on the CSP default-src list if this directive is 
 * undefined. See {@link http://www.w3.org/TR/CSP2/#directive-style-src}
 * 
 * @author Chris Smith
 *
 */
public class StyleSrcDirective extends AbstractUnsafeDirective {

	/**
	 * The name of the directive
	 */
	public static final String NAME = "style-src";

	public StyleSrcDirective() {
		super(StyleSrcDirective.NAME);
	}

	/**
	 * adds the value 'none' to the directive
	 * @return a reference to this object
	 */
	public StyleSrcDirective addNone() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_NONE);
		return this;
	}

	/**
	 * adds the value 'self' to the directive
	 * @return a reference to this object
	 */
	public StyleSrcDirective addSelf() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_SELF);
		return this;
	}

	/**
	 * adds the given value to the directive
	 * @param source the src-list attribute to add to the directive
	 * @return a reference to this object
	 */
	public StyleSrcDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}

	/**
	 * adds the value 'unsafe-inline' to the directive
	 * @return a reference to this object
	 */
	public StyleSrcDirective addUnsafeInline() {
		addDirectiveValue(AbstractUnsafeDirective.INLINE);
		return this;
	}

	/**
	 * adds the value 'unsafe-eval' to the directive
	 * @return a reference to this object
	 */
	public StyleSrcDirective addUnsafeEval() {
		addDirectiveValue(AbstractUnsafeDirective.EVAL);
		return this;
	}

	/**
	 * adds the value 'nonce-${nonce}' to the directive
	 * @param nonce the nonce value taken from {@link #generateNonce(int)}
	 * @return a reference to this object
	 */
	public StyleSrcDirective addNonce(String nonce) {
		addNewNonce(nonce);
		return this;
	}

	/**
	 * adds the value '${hashType}-${b64Hash}' to the directive
	 * @param hashType one of "sha256", "sha384", or "sha512"
	 * @param b64Hash a base-64 encoded hash of a script
	 * @return a reference to this object
	 */
	public StyleSrcDirective addHash(String hashType, String b64Hash) {
		addNewHash(hashType, b64Hash);
		return this;
	}
}
