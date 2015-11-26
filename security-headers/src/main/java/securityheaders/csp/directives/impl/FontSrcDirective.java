package securityheaders.csp.directives.impl;

import securityheaders.csp.directives.AbstractCSPDirective;
import securityheaders.csp.directives.AbstractSrcDirective;

public class FontSrcDirective extends AbstractSrcDirective {

	public static final String NAME = "font-src";

	public FontSrcDirective() {
		super(FontSrcDirective.NAME);
	}

	public FontSrcDirective addNone() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_NONE);
		return this;
	}

	public FontSrcDirective addSelf() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_SELF);
		return this;
	}

	public FontSrcDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}

}
