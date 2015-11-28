package securityheaders.csp.directives;

import securityheaders.csp.CSPValidationReport;

public abstract class AbstractSrcDirective extends AbstractCSPDirective {

	protected AbstractSrcDirective(String name) {
		super(name);
	}

	@Override
	public void validateAndReport(CSPValidationReport report) {
		if(this.directiveValues.size() > 1){
			if(this.directiveValues.contains(SRC_KEY_NONE)){
				report.addError(this, "Cannot contain multiple directive values where one is 'none'");
			}
			if(this.directiveValues.contains(SRC_WILDCARD)){
				report.addError(this, "Cannot contain multiple directive values where one is a wildcard");
			}
		}
		for (int i = 0; i < this.directiveValues.size(); i++) {
			String val = this.directiveValues.get(i);
			validateSourceListValue(val, report);
		}
		validateAdditional(report);
	}

	protected void validateAdditional(CSPValidationReport report) {
		//left for Overridding
	}
}
