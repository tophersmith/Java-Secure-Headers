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

import tophersmith.security.headers.csp.CSPValidationReport;
import tophersmith.security.headers.csp.directives.AbstractCSPDirective;
import tophersmith.security.headers.util.Validator;

/**
 * From 
 * <a href="https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet">
 * https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet</a>}
 * <br>
 * The frame-ancestors directive indicates whether the user agent should 
 * allow embedding the resource using a frame, iframe, object, embed or 
 * applet element, or equivalent functionality in non-HTML resources. 
 * See <a href="http://www.w3.org/TR/CSP2/#directive-base-uri">
 * http://www.w3.org/TR/CSP2/#directive-base-uri</a>
 * 
 * @author Chris Smith
 *
 */
public class FrameAncestorsDirective extends AbstractCSPDirective {

	/**
	 * The name of the directive
	 */
	public static final String NAME = "frame-ancestors";

	public FrameAncestorsDirective() {
		super(FrameAncestorsDirective.NAME);
	}

	/**
	 * adds the value 'none' to the directive
	 * @return a reference to this object
	 */
	public FrameAncestorsDirective addNone() {
		addDirectiveValue(Validator.SRC_KEY_NONE);
		return this;
	}

	/**
	 * adds the value 'self' to the directive
	 * @return a reference to this object
	 */
	public FrameAncestorsDirective addSelf() {
		addDirectiveValue(Validator.SRC_KEY_SELF);
		return this;
	}

	/**
	 * adds the given value to the directive
	 * @param source the src-list attribute to add to the directive
	 * @return a reference to this object
	 */
	public FrameAncestorsDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}

	@Override
	public void validateAndReport(CSPValidationReport report) {
		for (int i = 0; i < this.directiveValues.size(); i++) {
			String val = this.directiveValues.get(i);
			val = val.trim().toLowerCase();
			if (!Validator.isValidSrcKeyword(val) &&
					!Validator.isValidHostSource(val) && 
					!Validator.isValidSchemeSource(val)) {
				report.addError(this, "Ancestor Source " + val + 
						" is not one of host-source, scheme-source, 'self', or 'none'");
			}
		}
	}
}
