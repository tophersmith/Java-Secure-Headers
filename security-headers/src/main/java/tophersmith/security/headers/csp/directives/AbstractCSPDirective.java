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

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import tophersmith.security.headers.csp.CSPValidationReport;
import tophersmith.security.headers.util.Validator;

/**
 * The AbstractCSPDirective is the base implementation for all directive values
 * It handles basic validation and managing incoming directive values
 * 
 * @author Chris Smith
 *
 */
public abstract class AbstractCSPDirective {

	/**
	 * The list of RFC-compliance directive values
	 */
	protected final List<String> directiveValues;
	
	/**
	 * The list of non-RFC-compliance directive values
	 */
	protected final List<String> experimentalValues;
	
	/**
	 * The name of the directive
	 */
	protected final String name;

	protected AbstractCSPDirective(String name) {
		this.name = name;
		this.directiveValues = new ArrayList<String>();
		this.experimentalValues = new ArrayList<String>();
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
	 * append the given experimental directive value to this directive 
	 * if it is not null or empty
	 * @param value a directive value to add
	 */	
	 public void addExperimentalValue(String value){
		if (value != null && !value.trim().isEmpty()) {
			this.experimentalValues.add(value);
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

		if(!hasValidCharacters(test,report)){
			return;
		}
		
		if ( !isValidKeyword(test) && 
			 !Validator.isValidSchemeSource(test) && 
			 !Validator.isValidHostSource(test)) {
			report.addError(this, "Source value " + val + " could not be validated");
		}
	}
	
	/**
	 * Test if a given value does not contain any invalid characters.
	 * If the value contains an invalid character, a report message is filed
	 * 
	 * @param val a String to test
	 * @param report a validation report to hold any issues discovered 
	 * @return true if the value contains only legal values, false otherwise
	 */
	protected boolean hasValidCharacters(String val, CSPValidationReport report){
		boolean valid = Validator.hasValidCharacters(val);
		if(!valid){
			report.addError(this, "Source value " + val + " contains an illegal character");
		}
		return valid;
	}

	/**
	 * Validate any Keywords associated with this directive
	 * 
	 * @param val a directive value to validate
	 * @return true if this keyword is valid, false if it isn't or doesn't exist
	 */
	protected boolean isValidKeyword(String val) {
		return Validator.isValidSrcKeyword(val);
	}

	/**
	 * Convert this directive into a proper string representation
	 * including the experimental ones
	 * @return a string representation of this directive
	 */
	public String buildDirective() {
		if (this.directiveValues.size() == 0 &&
				this.experimentalValues.size() == 0) {
			return "";
		}
		return buildDirectiveValue();
	}
	
	/**
	 * Construct the directive line including the experimental ones
	 * @return the directive line describing this directive
	 */
	protected String buildDirectiveValue(){
		StringBuilder sb = new StringBuilder();
		sb.append(getDirectiveName());
		sb.append(buildStandardDirectiveValues());
		return sb.toString();
	}
	
	/**
	 * Build the normal directive values including the experimental ones
	 * @return the standard directive line describing this directive
	 */
	protected String buildStandardDirectiveValues(){
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < this.directiveValues.size(); i++) {
			sb.append(" ").append(this.directiveValues.get(i));
		}
		for (int i = 0; i < this.experimentalValues.size(); i++) {
			sb.append(" ").append(this.experimentalValues.get(i));
		}
		return sb.toString();
	}

	/**
	 * Get the list of directive values
	 * 
	 * @return a List of individual values
	 */
	public List<String> getDirectiveValues(){
		ArrayList<String> joined = new ArrayList<String>(
				this.directiveValues.size() + this.experimentalValues.size());
		joined.addAll(this.directiveValues);
		joined.addAll(this.experimentalValues);
		return Collections.unmodifiableList(joined);
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
