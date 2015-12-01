/*
 * Copyright 2015 Christopher Smith
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package securityheaders.csp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import securityheaders.csp.directives.AbstractCSPDirective;

/**
 * The CSPValidationReport holds errors and warnings related to validation of 
 * the CSP directives. In these reports, Errors denote issues with the 
 * directives that indicate a directive is incorrect and will not work if 
 * sent - e.g. the directive's value is not parseable. Warnings denote issues 
 * with the directives that indicate a directive is not accurate, but can still 
 * be sent with the intended outcome intact - e.g. the directive name is 
 * unknown. 
 * 
 * @author Chris Smith
 *
 */
public class CSPValidationReport {

	private final List<String> errors;
	private final List<String> warnings;

	CSPValidationReport() {
		this.errors = new ArrayList<String>();
		this.warnings = new ArrayList<String>();
	}

	/**
	 * does the report contain any warnings
	 * @return true if a warning has been registered with this report
	 */
	public boolean isWarningsEmpty() {
		return this.warnings.isEmpty();
	}

	/**
	 * does the report contain any errors
	 * @return true if a warning has been registered with this report
	 */
	public boolean isErrorsEmpty() {
		return this.errors.isEmpty();
	}

	/**
	 * register a new warning with this report
	 * @param directive the directive that has a validation failure
	 * @param report a validation report to hold any issues discovered 
	 */
	public void addWarning(AbstractCSPDirective directive, String report) {
		StringBuilder sb = new StringBuilder();
		sb.append(directive.getDirectiveName()).append(" reports a validation warning: ").append(report);
		this.warnings.add(sb.toString());
	}
	
	/**
	 * register a new error with this report
	 * @param directive the directive that has a validation failure
	 * @param report a validation report to hold any issues discovered 
	 */
	public void addError(AbstractCSPDirective directive, String report) {
		StringBuilder sb = new StringBuilder();
		sb.append(directive.getDirectiveName()).append(" reports a validation error: ").append(report);
		this.errors.add(sb.toString());
	}
	
	/**
	 * get a list of warnings for this report
	 * @return a list containing all warnings registered with this report
	 */
	public List<String> getWarningReports() {
		return Collections.unmodifiableList(this.warnings);
	}
	
	/**
	 * get a list of errors for this report
	 * @return a list containing all errors registered with this report
	 */
	public List<String> getErrorReports() {
		return Collections.unmodifiableList(this.errors);
	}

	/**
	 * remove all errors and warnings from this report so that the report
	 * may be run again
	 */
	public void reset() {
		this.errors.clear();
		this.warnings.clear();
	}
}
