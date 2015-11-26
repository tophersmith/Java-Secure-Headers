package securityheaders.csp.directives.impl;

import securityheaders.csp.directives.AbstractCSPDirective;
import securityheaders.csp.directives.AbstractSrcDirective;

public class FormActionDirective extends AbstractSrcDirective {

	public static final String NAME = "form-action";

	public FormActionDirective() {
		super(FormActionDirective.NAME);
	}

	public FormActionDirective addNone() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_NONE);
		return this;
	}

	public FormActionDirective addSelf() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_SELF);
		return this;
	}

	public FormActionDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}

}
