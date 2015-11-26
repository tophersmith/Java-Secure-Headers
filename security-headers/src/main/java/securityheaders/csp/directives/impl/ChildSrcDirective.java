package securityheaders.csp.directives.impl;

import securityheaders.csp.directives.AbstractCSPDirective;
import securityheaders.csp.directives.AbstractSrcDirective;

public class ChildSrcDirective extends AbstractSrcDirective {

	public static final String NAME = "child-src";

	public ChildSrcDirective() {
		super(ChildSrcDirective.NAME);
	}

	public ChildSrcDirective addNone() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_NONE);
		return this;
	}

	public ChildSrcDirective addSelf() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_SELF);
		return this;
	}

	public ChildSrcDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}

}
