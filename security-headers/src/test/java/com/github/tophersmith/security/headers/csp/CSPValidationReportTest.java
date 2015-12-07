package com.github.tophersmith.security.headers.csp;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.github.tophersmith.security.headers.csp.CSPValidationReport;
import com.github.tophersmith.security.headers.csp.directives.impl.DefaultSrcDirective;

public class CSPValidationReportTest {

	@Test
	public void testCSPValidationReportError() {
		CSPValidationReport report = new CSPValidationReport();
		String errorReport = "Error Report";
		report.addError(new DefaultSrcDirective(), errorReport);
		assertFalse(report.isErrorsEmpty());
		assertTrue(report.getErrorReports().get(0).contains(errorReport));
	}

	@Test
	public void testCSPValidationReportWarnings() {
		CSPValidationReport report = new CSPValidationReport();
		String warningReport = "Warning Report";
		report.addWarning(new DefaultSrcDirective(), warningReport);
		assertFalse(report.isWarningsEmpty());
		assertTrue(report.getWarningReports().get(0).contains(warningReport));
	}

	@Test
	public void testCSPValidationReportReset() {
		CSPValidationReport report = new CSPValidationReport();
		String warningReport = "Warning Report";
		report.addWarning(new DefaultSrcDirective(), warningReport);
		assertFalse(report.isWarningsEmpty());
		assertTrue(report.getWarningReports().get(0).contains(warningReport));
		report.reset();
		assertTrue(report.isWarningsEmpty());
	}
	
}
