package securityheaders.csp.directives.impl;

import java.net.URI;
import java.net.URISyntaxException;

import securityheaders.csp.CSPValidationReport;
import securityheaders.csp.directives.AbstractCSPDirective;

public class ReportUriDirective extends AbstractCSPDirective {

	public static final String NAME = "report-uri";

	public ReportUriDirective() {
		super(ReportUriDirective.NAME);
	}

	public ReportUriDirective addReportUri(String uri) {
		addDirectiveValue(uri);
		return this;
	}

	@Override
	public void validateAndReport(CSPValidationReport report) {
		for (int i = 0; i < this.directiveValues.size(); i++) {
			String val = this.directiveValues.get(i);
			try {
				new URI(val);
			} catch (URISyntaxException e) {
				report.addError(this, "Value " + val + " could not be parsed into a URI");
			}
		}
	}

}
