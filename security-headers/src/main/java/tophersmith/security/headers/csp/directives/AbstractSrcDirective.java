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
package tophersmith.security.headers.csp.directives;

import tophersmith.security.headers.csp.CSPValidationReport;

/**
 * The AbstractSrcDirective is a base class for all source-list based 
 * directives. It handles source-list validation.
 * 
 * @author Chris Smith
 *
 */
public abstract class AbstractSrcDirective extends AbstractCSPDirective {

	protected AbstractSrcDirective(String name) {
		super(name);
	}

	/**
	 * For this SrcDirective, ensure all values are 'none', *, or a source-list
	 * value. 
	 * @param report a validation report to hold any issues discovered
	 */
	@Override
	public void validateAndReport(CSPValidationReport report) {
		if(this.directiveValues.size() > 1){
			if(this.directiveValues.contains(SourceValidator.SRC_KEY_NONE)){
				report.addWarning(this, "Should not contain multiple directive values where one is 'none'");
			}
			if(this.directiveValues.contains(SourceValidator.SRC_WILDCARD)){
				report.addWarning(this, "Should not contain multiple directive values where one is a wildcard");
			}
		}
		for (int i = 0; i < this.directiveValues.size(); i++) {
			String val = this.directiveValues.get(i);
			validateSourceListValue(val, report);
		}
		for (int i = 0; i < this.experimentalValues.size(); i++) {
			String val = this.experimentalValues.get(i);
			hasValidCharacters(val, report);
		}
	}
}
