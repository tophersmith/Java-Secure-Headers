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

import topher.smith.security.headers.csp.directives.AbstractSrcDirective;
import topher.smith.security.headers.csp.directives.SourceValidator;

/**
 * From 
 * {@link https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet}
 * <br/>
 * The base-uri directive restricts the URLs that can be used to specify the 
 * document base URL. See {@link http://www.w3.org/TR/CSP2/#directive-base-uri}
 * 
 * @author Chris Smith
 *
 */
public class BaseUriDirective extends AbstractSrcDirective {
	
	/**
	 * The name of the directive
	 */
	public static final String NAME = "base-uri";

	public BaseUriDirective() {
		super(BaseUriDirective.NAME);
	}

	/**
	 * adds the value 'none' to the directive
	 * @return a reference to this object
	 */
	public BaseUriDirective addNone() {
		addDirectiveValue(SourceValidator.SRC_KEY_NONE);
		return this;
	}

	/**
	 * adds the value 'self' to the directive
	 * @return a reference to this object
	 */
	public BaseUriDirective addSelf() {
		addDirectiveValue(SourceValidator.SRC_KEY_SELF);
		return this;
	}

	/**
	 * adds the given value to the directive
	 * @param source the src-list attribute to add to the directive
	 * @return a reference to this object
	 */
	public BaseUriDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}
}
