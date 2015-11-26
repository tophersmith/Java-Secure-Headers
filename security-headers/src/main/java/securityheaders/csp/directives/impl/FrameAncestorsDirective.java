package securityheaders.csp.directives.impl;

import securityheaders.csp.CSPValidationReport;
import securityheaders.csp.directives.AbstractCSPDirective;

public class FrameAncestorsDirective extends AbstractCSPDirective {

	public static final String NAME = "frame-ancestors";

	public FrameAncestorsDirective() {
		super(FrameAncestorsDirective.NAME);
	}

	public FrameAncestorsDirective addNone() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_NONE);
		return this;
	}

	public FrameAncestorsDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}

	@Override
	public void validateAndReport(CSPValidationReport report) {
		for (int i = 0; i < this.directiveValues.size(); i++) {
			String val = this.directiveValues.get(i);
			val = val.trim().toLowerCase();
			if (!val.equals(AbstractCSPDirective.SRC_KEY_NONE) && !isHostSource(val) && !isSchemeSource(val)) {
				report.addReport(this,
						"Ancestor Source " + val + " is not one of host-source, scheme-source, or 'none'");
			}
		}
	}

}
