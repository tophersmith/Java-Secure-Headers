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

public class CSPValidationReport {

	private final List<String> errors;
	private final List<String> warnings;

	CSPValidationReport() {
		this.errors = new ArrayList<String>();
		this.warnings = new ArrayList<String>();
	}

	public boolean isWarningsEmpty() {
		return this.warnings.isEmpty();
	}
	
	public boolean isErrorsEmpty() {
		return this.errors.isEmpty();
	}

	public void addWarning(AbstractCSPDirective directive, String report) {
		StringBuilder sb = new StringBuilder();
		sb.append(directive.getDirectiveName()).append(" reports a validation warning: ").append(report);
		this.warnings.add(sb.toString());
	}

	public void addError(AbstractCSPDirective directive, String report) {
		StringBuilder sb = new StringBuilder();
		sb.append(directive.getDirectiveName()).append(" reports a validation error: ").append(report);
		this.errors.add(sb.toString());
	}
	
	public List<String> getWarningReports() {
		return Collections.unmodifiableList(this.warnings);
	}
	
	public List<String> getErrorReports() {
		return Collections.unmodifiableList(this.errors);
	}

	public void reset() {
		this.errors.clear();
		this.warnings.clear();
	}
}
