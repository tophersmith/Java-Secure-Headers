package securityheaders.csp.directives.impl;

import securityheaders.csp.directives.AbstractCSPDirective;
import securityheaders.csp.directives.AbstractSrcDirective;

public class DefaultSrcDirective extends AbstractSrcDirective {

	public static final String NAME = "default-src";

	public DefaultSrcDirective() {
		super(DefaultSrcDirective.NAME);
	}

	public DefaultSrcDirective addNone() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_NONE);
		return this;
	}

	public DefaultSrcDirective addSelf() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_SELF);
		return this;
	}

	public DefaultSrcDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}

}
