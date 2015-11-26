package securityheaders.impl;

import java.util.List;

import securityheaders.csp.ContentSecurityPolicy;
import securityheaders.util.InvalidHeaderException;

public class ContentSecurityPolicyHeader extends AbstractHeader {

	public static enum CSPHeaderName {
		CSP("Content-Security-Policy", "Content-Security-Policy-Report-Only"), XCSP("X-Content-Security-Policy",
				"X-Content-Security-Policy-Report-Only"), WEBKIT("X-Webkit-CSP", "X-Webkit-CSP-Report-Only"),;
		private final String primary;
		private final String report;

		private CSPHeaderName(String primary, String reportOnly) {
			this.primary = primary;
			this.report = reportOnly;
		}

		String getPrimaryName() {
			return this.primary;
		}

		String getReportName() {
			return this.report;
		}
	}

	private static final String LINE_SEPERATOR = System.lineSeparator();
	private boolean condense = false;
	private ContentSecurityPolicy csp = null;

	public ContentSecurityPolicyHeader(CSPHeaderName headerName) {
		this(headerName, false);
	}

	public ContentSecurityPolicyHeader(CSPHeaderName headerName, boolean reportOnly) {
		super(reportOnly ? headerName.getReportName() : headerName.getPrimaryName());
	}

	public ContentSecurityPolicyHeader setCondensed(boolean condense) {
		this.condense = condense;
		return this;
	}

	public ContentSecurityPolicyHeader setPolicy(ContentSecurityPolicy policy) {
		this.csp = policy;
		return this;
	}

	@Override
	public String buildHeaderValue() {
		String value = null;
		if (this.csp != null) {
			if (this.condense) {
				this.csp.compress();
			}
			value = this.csp.build();
		}
		return value;
	}

	@Override
	public void validate() throws InvalidHeaderException {
		this.csp.resetValidationReport();
		if (!this.csp.isValid()) {
			StringBuilder sb = new StringBuilder();
			sb.append("ContentSecurityPolicyHeader is invalid:").append(ContentSecurityPolicyHeader.LINE_SEPERATOR);
			List<String> reports = this.csp.getValidationReports();
			for (int i = 0; i < reports.size(); i++) {
				sb.append(reports.get(i)).append(ContentSecurityPolicyHeader.LINE_SEPERATOR);
			}
			throw new InvalidHeaderException(sb.toString());
		}
	}

}
