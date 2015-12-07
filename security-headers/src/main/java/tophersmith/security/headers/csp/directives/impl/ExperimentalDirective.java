package tophersmith.security.headers.csp.directives.impl;

import tophersmith.security.headers.csp.CSPValidationReport;
import tophersmith.security.headers.csp.directives.AbstractCSPDirective;

/**
 * Given the agility of the CSP feature, and the fact that certain browsers may
 * implement CSP directives without RFC compliance. This allows application
 * implementers to use these features without validation errors from this 
 * library.
 * 
 * @author Chris Smith
 *
 */
public class ExperimentalDirective extends AbstractCSPDirective{

	/**
	 * Experimental Directives need to have their names provided
	 * @param name the directive name of this experimental feature
	 */
	public ExperimentalDirective(String name) {
		super(name);
	}

	/**
	 * Experimental features of CSP are not validated other than
	 * basic character requirements
	 */
	@Override
	public void validateAndReport(CSPValidationReport report) {
		for (int i = 0; i < this.experimentalValues.size(); i++) {
			String val = this.experimentalValues.get(i);
			hasValidCharacters(val, report);
		}
	}

}
