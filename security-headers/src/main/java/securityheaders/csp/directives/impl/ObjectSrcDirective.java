package securityheaders.csp.directives.impl;

import securityheaders.csp.directives.AbstractCSPDirective;
import securityheaders.csp.directives.AbstractSrcDirective;

public class ObjectSrcDirective extends AbstractSrcDirective {

	public static final String NAME = "object-src";

	public ObjectSrcDirective() {
		super(ObjectSrcDirective.NAME);
	}

	public ObjectSrcDirective addNone() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_NONE);
		return this;
	}

	public ObjectSrcDirective addSelf() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_SELF);
		return this;
	}

	public ObjectSrcDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}

}
