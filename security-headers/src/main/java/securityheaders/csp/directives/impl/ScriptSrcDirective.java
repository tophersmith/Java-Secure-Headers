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
package securityheaders.csp.directives.impl;

import securityheaders.csp.directives.AbstractCSPDirective;
import securityheaders.csp.directives.AbstractInlineDirective;

public class ScriptSrcDirective extends AbstractInlineDirective {

	public static final String NAME = "script-src";

	public ScriptSrcDirective() {
		super(ScriptSrcDirective.NAME);
	}

	public ScriptSrcDirective addNone() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_NONE);
		return this;
	}

	public ScriptSrcDirective addSelf() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_SELF);
		return this;
	}

	public ScriptSrcDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}

	public ScriptSrcDirective addUnsafeInline() {
		addDirectiveValue(AbstractInlineDirective.INLINE);
		return this;
	}

	public ScriptSrcDirective addUnsafeEval() {
		addDirectiveValue(AbstractInlineDirective.EVAL);
		return this;
	}

	public ScriptSrcDirective addNonce(String nonce) {
		addNewNonce(nonce);
		return this;
	}

	public ScriptSrcDirective addHash(String hashType, String b64Hash) {
		addNewHash(hashType, b64Hash);
		return this;
	}

}
