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
package com.github.tophersmith.security.headers.csp.directives.impl;

import com.github.tophersmith.security.headers.csp.CSPValidationReport;
import com.github.tophersmith.security.headers.csp.directives.AbstractCSPDirective;

/**
 * From 
 * {@link https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet}
 * <br/>
 * The sandbox directive specifies an HTML sandbox policy that the user 
 * agent applies to the protected resource. Optional in CSP 1.0. See 
 * {@link http://www.w3.org/TR/CSP2/#directive-sandbox}
 * 
 * @author Chris Smith
 *
 */
public class SandboxDirective extends AbstractCSPDirective {

	/**
	 * The name of the directive
	 */
	public static final String NAME = "sandbox";

	private static final String FORMS = "allow-forms";
	private static final String POINTER_LOCK = "allow-pointer-lock";
	private static final String POPUPS = "allow-popups";
	private static final String SAME_ORIGIN = "allow-same-origin";
	private static final String SCRIPTS = "allow-scripts";
	private static final String TOP_NAV = "allow-top-navigation";

	public SandboxDirective() {
		super(SandboxDirective.NAME);
	}

	/**
	 * adds the value allow-forms to the directive
	 * @return a reference to this object
	 */
	public SandboxDirective addAllowForms() {
		addDirectiveValue(SandboxDirective.FORMS);
		return this;
	}

	/**
	 * adds the value allow-pointer-lock to the directive
	 * @return a reference to this object
	 */
	public SandboxDirective addAllowPointerLock() {
		addDirectiveValue(SandboxDirective.POINTER_LOCK);
		return this;
	}

	/**
	 * adds the value allow-popups to the directive
	 * @return a reference to this object
	 */
	public SandboxDirective addAllowPopups() {
		addDirectiveValue(SandboxDirective.POPUPS);
		return this;
	}

	/**
	 * adds the value allow-same-origin to the directive
	 * @return a reference to this object
	 */
	public SandboxDirective addAllowSameOrigin() {
		addDirectiveValue(SandboxDirective.SAME_ORIGIN);
		return this;
	}

	/**
	 * adds the value allow-scripts to the directive
	 * @return a reference to this object
	 */
	public SandboxDirective addAllowScripts() {
		addDirectiveValue(SandboxDirective.SCRIPTS);
		return this;
	}

	/**
	 * adds the value allow-top-navigation to the directive
	 * @return a reference to this object
	 */
	public SandboxDirective addAllowTopNavigation() {
		addDirectiveValue(SandboxDirective.TOP_NAV);
		return this;
	}

	@Override
	public void validateAndReport(CSPValidationReport report) {
		// this cannot be incorrect
	}
}
