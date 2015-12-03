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
import java.util.regex.Pattern;

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

	public static final String SRC_WILDCARD = "*";
	public static final String SRC_KEY_NONE = "'none'";
	public static final String SRC_KEY_SELF = "'self'";
	public static final String SRC_UNSAFE_INLINE = "'unsafe-inline'";
	public static final String SRC_UNSAFE_EVAL = "'unsafe-eval'";

	//these characters may not exist in any directive value
	private static final String[] ILLEGAL_SRC_CHARS = { " ", ";", "," };

	// 1 letter plus optional letters, digits, +, -, or .
	private static final String SCHEME_PART = "\\w{1}(?:[\\w\\d\\+\\-\\.])*";
	
	// * OR Optional *. plus 1 or more letters/digits plus optional . plus 1 or more letters/digits
	private static final String HOST_PART = "(?:[*])|(?:(?:\\*\\.)?[\\w\\d]{1}(?:[\\.]?[\\d\\w])+)";
	
	// : followed by either 1 or more digits or *
	private static final String PORT_PART = ":(?:[\\d]+|\\*)";
	
	// a slash optionally followed by a non-slash character followed by any characters
	private static final String PATH_PART = "(?:\\/(?:[^/][\\w\\d]*))+";
	
	//host-source definition
	private static final Pattern HOST_SOURCE = Pattern.compile("^" + // match start of string
							"(" + AbstractCSPDirective.SCHEME_PART + ":\\/\\/)?" + // scheme-part is optional
							"(" + AbstractCSPDirective.HOST_PART + ")" + // host-part is required
							"(" + AbstractCSPDirective.PORT_PART + ")?" + // port-part is optional
							"(" + AbstractCSPDirective.PATH_PART + ")?" + // path-part is optional
							"$");//match end of string
	
	//scheme-source definition
	private static final Pattern SCHEME_SOURCE = Pattern.compile("^" + AbstractCSPDirective.SCHEME_PART + ":$");

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
		for (int i = 0; i < AbstractCSPDirective.ILLEGAL_SRC_CHARS.length; i++) {
			if (test.contains(AbstractCSPDirective.ILLEGAL_SRC_CHARS[i])) {
				report.addError(this, "Source value " + val + " contains an illegal character: " + AbstractCSPDirective.ILLEGAL_SRC_CHARS[i]);
				return;
			}
		}

		if (!test.equals(AbstractCSPDirective.SRC_KEY_SELF) && 
				!test.equals(AbstractCSPDirective.SRC_KEY_NONE) && 
				!isValidKeyword(test, report) && 
				!isSchemeSource(test) && 
				!isHostSource(test)) {
			report.addError(this, "Source value " + val + " could not be validated");
		}
	}

	/**
	 * match a host-source value
	 * @param val a directive value to validate
	 * @return true if this directive value is a host-source value
	 */
	protected boolean isHostSource(String val) {
		return AbstractCSPDirective.HOST_SOURCE.matcher(val).find();
	}

	/**
	 * match a scheme-source value
	 * @param val a directive value to validate
	 * @return true if this directive value is a scheme-source value
	 */
	protected boolean isSchemeSource(String val) {
		return AbstractCSPDirective.SCHEME_SOURCE.matcher(val).find();
	}

	/**
	 * Validate any Keywords associated with this directive
	 * 
	 * @param val a directive value to validate
	 * @param report a validation report to hold any issues discovered
	 * @return true if this keyword is valid, false if it isn't or doesn't exist
	 */
	protected boolean isValidKeyword(String val, CSPValidationReport report) {
		return false;
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
