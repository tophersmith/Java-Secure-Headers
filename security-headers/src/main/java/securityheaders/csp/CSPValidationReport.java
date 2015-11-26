package securityheaders.csp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import securityheaders.csp.directives.AbstractCSPDirective;

public class CSPValidationReport {

	private final List<String> reportInformation;

	CSPValidationReport() {
		this.reportInformation = new ArrayList<String>();
	}

	public boolean isEmpty() {
		return this.reportInformation.isEmpty();
	}

	public void addReport(AbstractCSPDirective directive, String report) {
		StringBuilder sb = new StringBuilder();
		sb.append(directive.getDirectiveName()).append(" reports a validation failure: ").append(report);
		this.reportInformation.add(sb.toString());
	}

	public List<String> getReports() {
		return Collections.unmodifiableList(this.reportInformation);
	}

	public void reset() {
		this.reportInformation.clear();
	}
}
