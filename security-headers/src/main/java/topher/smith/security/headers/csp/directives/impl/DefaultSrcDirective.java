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
package topher.smith.security.headers.csp.directives.impl;

import topher.smith.security.headers.csp.directives.AbstractCSPDirective;
import topher.smith.security.headers.csp.directives.AbstractSrcDirective;

/**
 * From 
 * {@link https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet}
 * <br/>
 * The default-src directive governs the default src-list of other directives. 
 * These include: 
 * <ul>
 * <li>child-src</li>
 * <li>connect-src</li>
 * <li>font-src</li>
 * <li>img-src</li>
 * <li>media-src</li>
 * <li>object-src</li>
 * <li>script-src</li>
 * <li>style-src</li>
 * </ul>
 * See {@link http://www.w3.org/TR/CSP2/#directive-default-src}
 * 
 * @author Chris Smith
 *
 */
public class DefaultSrcDirective extends AbstractSrcDirective {
	
	/**
	 * The name of the directive
	 */
	public static final String NAME = "default-src";

	public DefaultSrcDirective() {
		super(DefaultSrcDirective.NAME);
	}

	/**
	 * adds the value 'none' to the directive
	 * @return a reference to this object
	 */
	public DefaultSrcDirective addNone() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_NONE);
		return this;
	}

	/**
	 * adds the value 'self' to the directive
	 * @return a reference to this object
	 */
	public DefaultSrcDirective addSelf() {
		addDirectiveValue(AbstractCSPDirective.SRC_KEY_SELF);
		return this;
	}

	/**
	 * adds the given value to the directive
	 * @param source the src-list attribute to add to the directive
	 * @return a reference to this object
	 */
	public DefaultSrcDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}
}
