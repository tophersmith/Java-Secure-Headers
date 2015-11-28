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

import securityheaders.csp.CSPValidationReport;
import securityheaders.csp.directives.AbstractCSPDirective;

public class PluginTypesDirective extends AbstractCSPDirective {

	public static final String NAME = "plugin-types";

	public PluginTypesDirective() {
		super(PluginTypesDirective.NAME);
	}

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
