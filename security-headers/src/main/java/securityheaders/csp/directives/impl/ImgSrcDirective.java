package securityheaders.csp.directives.impl;

import securityheaders.csp.directives.AbstractCSPDirective;
import securityheaders.csp.directives.AbstractSrcDirective;

public class ImgSrcDirective extends AbstractSrcDirective {

	public static final String NAME = "img-src";

	public ImgSrcDirective() {
		super(ImgSrcDirective.NAME);
	}

	public ImgSrcDirective addNone() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_NONE);
		return this;
	}

	public ImgSrcDirective addSelf() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_SELF);
		return this;
	}

	public ImgSrcDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}

}
