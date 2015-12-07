package tophersmith.security.headers.csp;

/**
 * Defines the available header names for CSP
 * Defines both the standard(violation mode) header as well as the 
 * report only header
 * 
 * @author Chris Smith
 *
 */
public enum CSPHeaderName {
	/**
	 * Standard CSP Header
	 */
	CSP("Content-Security-Policy", "Content-Security-Policy-Report-Only"), 
	
	/**
	 * Standard CSP Header
	 */
	XCSP("X-Content-Security-Policy", "X-Content-Security-Policy-Report-Only"), 
	
	/**
	 * Standard CSP Header
	 */
	WEBKIT("X-Webkit-CSP", "X-Webkit-CSP-Report-Only"),
	;
	
	private final String primary;
	private final String report;

	private CSPHeaderName(String primary, String reportOnly) {
		this.primary = primary;
		this.report = reportOnly;
	}

	/**
	 * return the normal name for this CSP (the violation-mode)
	 * @return the normal name of this CSP
	 */
	public String getPrimaryName() {
		return this.primary;
	}

	/**
	 * return the report name for this CSP (the report-only-mode)
	 * @return the report-only name of this CSP
	 */
	public String getReportName() {
		return this.report;
	}
}