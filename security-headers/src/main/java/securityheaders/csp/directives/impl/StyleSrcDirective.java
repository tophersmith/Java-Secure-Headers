package securityheaders.csp.directives.impl;

import securityheaders.csp.directives.AbstractCSPDirective;
import securityheaders.csp.directives.AbstractInlineDirective;

public class StyleSrcDirective extends AbstractInlineDirective {

	public static final String NAME = "style-src";

	public StyleSrcDirective() {
		super(StyleSrcDirective.NAME);
	}

	public StyleSrcDirective addNone() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_NONE);
		return this;
	}

	public StyleSrcDirective addSelf() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_SELF);
		return this;
	}

	public StyleSrcDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}

	public StyleSrcDirective addUnsafeInline(boolean allow) {
		addDirectiveValue(AbstractInlineDirective.INLINE);
		return this;
	}

	public StyleSrcDirective addUnsafeEval(boolean allow) {
		addDirectiveValue(AbstractInlineDirective.EVAL);
		return this;
	}

	public StyleSrcDirective addNonce(String nonce) {
		addNewNonce(nonce);
		return this;
	}

	public StyleSrcDirective addHash(String hashType, String b64Hash) {
		addNewHash(hashType, b64Hash);
		return this;
	}

}
