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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import securityheaders.csp.directives.AbstractCSPDirective;
import securityheaders.csp.directives.impl.ChildSrcDirective;
import securityheaders.csp.directives.impl.ConnectSrcDirective;
import securityheaders.csp.directives.impl.DefaultSrcDirective;
import securityheaders.csp.directives.impl.FontSrcDirective;
import securityheaders.csp.directives.impl.ImgSrcDirective;
import securityheaders.csp.directives.impl.MediaSrcDirective;
import securityheaders.csp.directives.impl.ObjectSrcDirective;
import securityheaders.csp.directives.impl.ScriptSrcDirective;
import securityheaders.csp.directives.impl.StyleSrcDirective;

public class ContentSecurityPolicy {

	private final Map<String, AbstractCSPDirective> directiveMap;
	private final CSPValidationReport validationReport;
	private final PolicyLevel level;
	
	private static final String[] RELY_ON_DEFAULT = { ChildSrcDirective.NAME, ConnectSrcDirective.NAME,
			FontSrcDirective.NAME, ImgSrcDirective.NAME, MediaSrcDirective.NAME, ObjectSrcDirective.NAME,
			ScriptSrcDirective.NAME, StyleSrcDirective.NAME };

	public ContentSecurityPolicy(){
		this(PolicyLevel.CSP2);
	}
	
	public ContentSecurityPolicy(PolicyLevel level) {
		this.directiveMap = new HashMap<String, AbstractCSPDirective>();
		this.validationReport = new CSPValidationReport();
		this.level = level;
	}

	// add to the map
	public ContentSecurityPolicy addDirective(AbstractCSPDirective directive) {
		this.directiveMap.put(directive.getDirectiveName(), directive);
		return this;
	}

	// remove duplicates from policy
	public ContentSecurityPolicy compress() {
		for (String key : this.directiveMap.keySet()) {
			AbstractCSPDirective directive = this.directiveMap.get(key);
			directive.removeInternalDuplicates();
		}
		if (this.directiveMap.containsKey(DefaultSrcDirective.NAME)) {
			removeDefaultDuplicates();
		}
		return this;
	}
	
	private void removeDefaultDuplicates(){
		DefaultSrcDirective defaultDir = (DefaultSrcDirective) this.directiveMap.get(DefaultSrcDirective.NAME);
		for (int i = 0; i < ContentSecurityPolicy.RELY_ON_DEFAULT.length; i++) {
			AbstractCSPDirective directive = this.directiveMap.get(ContentSecurityPolicy.RELY_ON_DEFAULT[i]);
			directive.removeDuplicatesOf(defaultDir);
		}
	}

	public void resetValidationReport() {
		this.validationReport.reset();
	}

	// validate all policy pieces
	public boolean isValid() {
		for (String key : this.directiveMap.keySet()) {
			AbstractCSPDirective directive = this.directiveMap.get(key);
			directive.validateAndReport(this.validationReport);
			if(!this.level.isAllowed(key)){
				this.validationReport.addWarning(directive, this.level.name() + " does not define directive " + key);			
			}
			if(!this.level.isDeprecated(key)){
				this.validationReport.addWarning(directive, this.level.name() + " has deprecated directive " + key);
			}
		}
		return this.validationReport.isErrorsEmpty();
	}

	public boolean hasWarnings(){
		return this.validationReport.isWarningsEmpty();
	}
	// can return empty list
	public List<String> getValidationErrorReports() {
		return this.validationReport.getErrorReports();
	}
	
	public List<String> getValidationWarningReports(){
		return this.validationReport.getWarningReports();
	}

	// return a string of the policy after removing invalid pieces
	public String build() {
		StringBuilder sb = new StringBuilder();
		for (String key : this.directiveMap.keySet()) {
			AbstractCSPDirective directive = this.directiveMap.get(key);
			sb.append(directive.buildDirective()).append("; ");
		}
		return sb.toString();
	}
}
