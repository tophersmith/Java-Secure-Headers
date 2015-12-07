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

/**
 * From 
 * <a href="https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet">
 * https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet</a>}
 * <br/>
 * The plugin-types directive restricts the set of plugins that can be 
 * invoked by the protected resource by limiting the types of resources 
 * that can be embedded. See 
 * <a href="http://www.w3.org/TR/CSP2/#directive-base-uri">
 * http://www.w3.org/TR/CSP2/#directive-base-uri</a>
 * 
 * @author Chris Smith
 *
 */
public class PluginTypesDirective extends AbstractCSPDirective {

	/**
	 * The name of the directive
	 */
	public static final String NAME = "plugin-types";

	public PluginTypesDirective() {
		super(PluginTypesDirective.NAME);
	}

	/**
	 * adds the given media-type to the directive
	 * @param mediaType a MIME type
	 * @return a reference to this object
	 */
	public PluginTypesDirective addMediaType(String mediaType) {
		this.directiveValues.add(mediaType);
		return this;
	}

	@Override
	public void validateAndReport(CSPValidationReport report) {
		for (int i = 0; i < this.directiveValues.size(); i++) {
			String val = this.directiveValues.get(i);
			String[] split = val.split("/");
			if (split.length != 2 || split[0].trim().length() == 0 || split[1].trim().length() == 0) {
				report.addError(this, "Media type: " + val + " is not valid. It must contain a value, a slash, and another value");
			}
		}
	}
}
