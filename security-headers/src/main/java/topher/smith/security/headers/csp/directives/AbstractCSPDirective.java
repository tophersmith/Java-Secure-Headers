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
package topher.smith.security.headers.csp.directives;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import topher.smith.security.headers.csp.CSPValidationReport;

/**
 * The AbstractCSPDirective is the base implementation for all directive values
 * It handles basic validation and managing incoming directive values
 * 
 * @author Chris Smith
 *
 */
public abstract class AbstractCSPDirective {

	protected final List<String> directiveValues;
	protected final String name;

	protected AbstractCSPDirective(String name) {
		this.name = name;
		this.directiveValues = new ArrayList<String>();
	}

	/**
	 * get this directive's proper name
	 * @return an RFC-compliant directive name
	 */
	public String getDirectiveName() {
		return this.name;
	}

	/**
	 * append the given directive value to this directive if it 
	 * is not null or empty
	 * @param value a directive value to add
	 */
	protected void addDirectiveValue(String value) {
		if (value != null && !value.trim().isEmpty()) {
			this.directiveValues.add(value);
		}
	}

	/**
	 * Validate a given directive value as a source-list. Report any validation
	 * errors to the provided report
	 * 
	 * @param val a directive value to validate
	 * @param report a validation report to hold any issues discovered 
	 */
	protected void validateSourceListValue(String val, CSPValidationReport report) {
		String test = val.trim().toLowerCase();

		if(!SourceValidator.hasValidCharacters(test)){
			report.addError(this, "Source value " + val + " contains an illegal character: " + SourceValidator.ILLEGAL_SRC_CHARS);
			return;
		}
		
		if ( !isValidKeyword(test) && 
			 !SourceValidator.isValidSchemeSource(test) && 
			 !SourceValidator.isValidHostSource(test)) {
			report.addError(this, "Source value " + val + " could not be validated");
		}
	}

	/**
	 * Validate any Keywords associated with this directive
	 * 
	 * @param val a directive value to validate
	 * @param report a validation report to hold any issues discovered
	 * @return true if this keyword is valid, false if it isn't or doesn't exist
	 */
	protected boolean isValidKeyword(String val) {
		return SourceValidator.isValidSrcKeyword(val);
	}

	/**
	 * Convert this directive into a proper string representation
	 * @return a string representation of this directive
	 */
	public String buildDirective() {
		StringBuilder sb = new StringBuilder();
		if (this.directiveValues.size() > 0) {
			sb.append(getDirectiveName());
			for (int i = 0; i < this.directiveValues.size(); i++) {
				sb.append(" ").append(this.directiveValues.get(i));
			}
			sb.append(buildCustomDirective());
		}
		return sb.toString();
	}

	/**
	 * OVERRIDE THIS IF NEEDED
	 * @return a String containing any additional directive values
	 */
	protected String buildCustomDirective() {
		return "";
	}

	/**
	 * Get the list of directive values
	 * 
	 * @return a List of individual values
	 */
	public List<String> getDirectiveValues(){
		return Collections.unmodifiableList(this.directiveValues);
	}
	
	/**
	 * Within this directive, remove any duplicate values
	 */
	public void removeInternalDuplicates() {
		Set<String> deduped = new LinkedHashSet<String>(this.directiveValues);
		this.directiveValues.clear();
		this.directiveValues.addAll(deduped);
	}

	/**
	 * For this CSPDirective, ensure all values are correctly set up for the 
	 * directive and add validation errors to the provided CSPValidationReport
	 * 
	 * @param report a validation report to hold any issues discovered
	 */
	public abstract void validateAndReport(CSPValidationReport report);
}
