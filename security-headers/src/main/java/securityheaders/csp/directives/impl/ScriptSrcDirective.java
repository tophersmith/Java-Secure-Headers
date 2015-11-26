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
