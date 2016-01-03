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
package tophersmith.security.headers.csp;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

import tophersmith.security.headers.csp.directives.AbstractCSPDirective;

/**
 * A Content Security Policy defines several directives that indicate from 
 * where certain kinds of content may be loaded. This is sent via a 
 * declarative list in an HTTP Response header. A Browser's User-Agent takes
 * this policy into consideration when loading resources into the browser.
 * This protects the browser from a wide array of content injection 
 * vulnerabilities. The CSP is a "Defense-in-Depth" strategy component and 
 * should be used alongside other defenses, such as input validation.
 * <br><br>
 * Example:<br>
 * <code>
 * ContentSecurityPolicy csp = new ContentSecurityPolicy();<br>
 * DefaultSrcDirective defaultDir = new DefaultSrcDirective().addSelf();<br>
 * ScriptSrcDirective scriptDir = new ScriptSrcDirective().addSelf().addUnsafeInline().addUnsafeEval();<br>
 * csp.addDirective(defaultDir).addDirective(scriptDir);<br>
 * csp.build();
 * </code><br>
 * The build method would return default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'
 * 
 * @author Chris Smith
 *
 */
public class ContentSecurityPolicy {

	private final Map<String, AbstractCSPDirective> directiveMap;
	private final CSPValidationReport validationReport;
	private final PolicyLevel level;
	
	/**
	 * Creates a new ContentSecurityPolicy with a PolicyLevel of CSPv2
	 */
	public ContentSecurityPolicy(){
		this(PolicyLevel.CSP2);
	}
	
	/**
	 * Create a new ContentSecurityPolicy using the given PolicyLevel
	 * @param level a PolicyLevel to validate against
	 */
	public ContentSecurityPolicy(PolicyLevel level) {
		this.directiveMap = new ConcurrentHashMap<String, AbstractCSPDirective>();
		this.validationReport = new CSPValidationReport();
		this.level = level;
	}

	/**
	 * adds a new CSPDirective to this policy. This directive replaces any 
	 * previously defined directive of the same type
	 * @param directive a new directive to be attached to this policy
	 * @return a reference to this object
	 */
	public ContentSecurityPolicy addDirective(AbstractCSPDirective directive) {
		this.directiveMap.put(directive.getDirectiveName(), directive);
		return this;
	}

	/**
	 * Retrieve a CSP Directive by name
	 * @param directiveName suggested to use the AbstractCSPDirective's NAME value
	 * @return a directive denoted by the supplied directiveName or null
	 */
	public AbstractCSPDirective getDirective(String directiveName){
		AbstractCSPDirective dir = null;
		if(directiveName != null && this.directiveMap.containsKey(directiveName)){
			dir = this.directiveMap.get(directiveName);
		}
		return dir;
	}
	
	/**
	 * Attempts to reduce a policy to its most compressed version. This
	 * transformation occurs in place, therefore post-compression some data 
	 * may be lost
	 * @return a reference to this object
	 */
	public ContentSecurityPolicy reduce() {
		for (Entry<String, AbstractCSPDirective> entry  : this.directiveMap.entrySet()) {
			AbstractCSPDirective directive = entry.getValue();
			directive.removeInternalDuplicates();
		}
		removeEmptyDirectives();
		return this;
	}
	
	/**
	 * searches all directives for any that do not define values and removes
	 * them from this policy
	 */
	private void removeEmptyDirectives() {
		Iterator<Entry<String,AbstractCSPDirective>> iter = this.directiveMap.entrySet().iterator();
		while (iter.hasNext()) {
			Entry<String,AbstractCSPDirective> entry = iter.next();
			AbstractCSPDirective directive = entry.getValue();
			if(directive.getDirectiveValues().size() == 0){
				this.directiveMap.remove(directive.getDirectiveName());
			}
		}
	}

	/**
	 * clears the validation report attached to this policy so that validation
	 * may be re-run
	 */
	public void resetValidationReport() {
		this.validationReport.reset();
	}

	/**
	 * For each directive defined on this policy, attempt to validate the 
	 * directive, filling the validation report with any validation issues
	 * discovered
	 * @return true if no validation <u>errors</u> occurred.
	 */
	public boolean isValid() {
		for (Entry<String, AbstractCSPDirective> entry  : this.directiveMap.entrySet()) {
			String key = entry.getKey();
			AbstractCSPDirective directive = entry.getValue();
			directive.validateAndReport(this.validationReport);
			if(!this.level.isDefined(directive)){
				this.validationReport.addWarning(directive, this.level.name() + " does not define directive " + key);			
			}
			if(this.level.isDeprecated(directive)){
				this.validationReport.addWarning(directive, this.level.name() + " has deprecated directive " + key);
			}
		}
		return this.validationReport.isErrorsEmpty();
	}

	/**
	 * get the list of errors attached to the validation report
	 * @return a List of errors encountered during validation
	 */
	public List<String> getValidationErrorReports() {
		return this.validationReport.getErrorReports();
	}
	
	/**
	 * get the list of warnings attached to the validation report
	 * @return a List of warnings encountered during validation
	 */
	public List<String> getValidationWarningReports(){
		return this.validationReport.getWarningReports();
	}

	/**
	 * Construct a String representation of the policy using the defined
	 * CSP directives
	 * @return a String representation of this policy
	 */
	public String build() {
		StringBuilder sb = new StringBuilder();
		boolean first = true;
		for (Entry<String, AbstractCSPDirective> entry  : this.directiveMap.entrySet()) {
			AbstractCSPDirective directive = entry.getValue();
			if(first){
				first = false;
			} else{
				sb.append("; ");
			}
			sb.append(directive.buildDirective());
		}
		return sb.toString();
	}
}
