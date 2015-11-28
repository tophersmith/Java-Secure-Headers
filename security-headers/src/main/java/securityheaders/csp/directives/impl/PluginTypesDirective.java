package securityheaders.csp.directives.impl;

import securityheaders.csp.CSPValidationReport;
import securityheaders.csp.directives.AbstractCSPDirective;

public class PluginTypesDirective extends AbstractCSPDirective {

	public static final String NAME = "plugin-types";

	public PluginTypesDirective() {
		super(PluginTypesDirective.NAME);
	}

	public PluginTypesDirective addMediaType(String mediaType) {
		this.directiveValues.add(mediaType);
		return this;
	}

	@Override
	public void validateAndReport(CSPValidationReport report) {
		for (int i = 0; i < this.directiveValues.size(); i++) {
			String val = this.directiveValues.get(i);
			String[] split = val.split("/");
			if (split.length != 2 || split[0].trim().length() == 0 || split[1].trim().length() == 0) {
				report.addError(this, "Media type: " + val + " is not valid. It must contain a value, a slash, and another value");
			}
		}
	}
}
