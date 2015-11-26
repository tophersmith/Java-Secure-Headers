package securityheaders.csp.directives.impl;

import securityheaders.csp.directives.AbstractCSPDirective;
import securityheaders.csp.directives.AbstractSrcDirective;

public class BaseUriDirective extends AbstractSrcDirective {

	public static final String NAME = "base-uri";

	public BaseUriDirective() {
		super(BaseUriDirective.NAME);
	}

	public BaseUriDirective addNone() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_NONE);
		return this;
	}

	public BaseUriDirective addSelf() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_SELF);
		return this;
	}

	public BaseUriDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}
}
