package securityheaders.csp.directives.impl;

import securityheaders.csp.directives.AbstractCSPDirective;
import securityheaders.csp.directives.AbstractSrcDirective;

public class FrameSrcDirective extends AbstractSrcDirective {

	public static final String NAME = "frame-src";

	public FrameSrcDirective() {
		super(FrameSrcDirective.NAME);
	}

	public FrameSrcDirective addNone() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_NONE);
		return this;
	}

	public FrameSrcDirective addSelf() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_SELF);
		return this;
	}

	public FrameSrcDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}

}
