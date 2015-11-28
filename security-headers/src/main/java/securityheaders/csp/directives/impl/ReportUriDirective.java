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
