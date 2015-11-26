package securityheaders.csp.directives.impl;

import securityheaders.csp.directives.AbstractCSPDirective;
import securityheaders.csp.directives.AbstractSrcDirective;

public class MediaSrcDirective extends AbstractSrcDirective {

	public static final String NAME = "media-src";

	public MediaSrcDirective() {
		super(MediaSrcDirective.NAME);
	}

	public MediaSrcDirective addNone() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_NONE);
		return this;
	}

	public MediaSrcDirective addSelf() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_SELF);
		return this;
	}

	public MediaSrcDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}

}
