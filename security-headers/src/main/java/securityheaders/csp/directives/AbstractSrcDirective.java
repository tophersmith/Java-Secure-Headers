package securityheaders.csp.directives;

import securityheaders.csp.CSPValidationReport;

public abstract class AbstractSrcDirective extends AbstractCSPDirective {

	protected AbstractSrcDirective(String name) {
		super(name);
	}

	@Override
	public void validateAndReport(CSPValidationReport report) {
		for (int i = 0; i < this.directiveValues.size(); i++) {
			String val = this.directiveValues.get(i);
			validateSourceListValue(val, report);
		}
		validateAdditional(report);
	}

	protected void validateAdditional(CSPValidationReport report) {

	}
}
