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
package tophersmith.security.headers.csp.directives.impl;

import org.apache.commons.validator.routines.UrlValidator;

import tophersmith.security.headers.csp.CSPValidationReport;
import tophersmith.security.headers.csp.directives.AbstractCSPDirective;

/**
 * From 
 * {@link https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet}
 * <br/>
 * The report-uri directive specifies a URL to which the user agent sends 
 * reports about policy violation. See 
 * {@link http://www.w3.org/TR/CSP2/#directive-report-uri}
 * 
 * @author Chris Smith
 *
 */
public class ReportUriDirective extends AbstractCSPDirective {

	/**
	 * The name of the directive
	 */
	public static final String NAME = "report-uri";
	private static final UrlValidator urlValidator = UrlValidator.getInstance();
	
	public ReportUriDirective() {
		super(ReportUriDirective.NAME);
	}

	/**
	 * adds the given URL to the directive
	 * @param uri a URL endpoint that accepts CSP violation reports
	 * @return
	 */
	public ReportUriDirective addReportUri(String uri) {
		addDirectiveValue(uri);
		return this;
	}

	@Override
	public void validateAndReport(CSPValidationReport report) {
		for (int i = 0; i < this.directiveValues.size(); i++) {
			String val = this.directiveValues.get(i);
			if(!urlValidator.isValid(val)){
				report.addError(this, "Value " + val + " could not be parsed into a URI");
			}
		}
	}
}
