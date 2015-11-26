package securityheaders.csp.directives.impl;

import securityheaders.csp.directives.AbstractCSPDirective;
import securityheaders.csp.directives.AbstractSrcDirective;

public class ConnectSrcDirective extends AbstractSrcDirective {

	public static final String NAME = "connect-src";

	public ConnectSrcDirective() {
		super(ConnectSrcDirective.NAME);
	}

	public ConnectSrcDirective addNone() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_NONE);
		return this;
	}

	public ConnectSrcDirective addSelf() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_SELF);
		return this;
	}

	public ConnectSrcDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}

}
