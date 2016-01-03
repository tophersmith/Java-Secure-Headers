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

import tophersmith.security.headers.csp.directives.AbstractSrcDirective;
import tophersmith.security.headers.util.Validator;

/**
 * From 
 * <a href="https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet">
 * https://www.owasp.org/index.php/Content_Security_Policy_Cheat_Sheet</a>}
 * <br>
 * The object-src directive restricts from where the protected resource can 
 * load plugins. This directive relies on the CSP default-src list if this 
 * directive is undefined. See 
 * <a href="http://www.w3.org/TR/CSP2/#directive-base-uri">
 * http://www.w3.org/TR/CSP2/#directive-base-uri</a>
 * 
 * @author Chris Smith
 *
 */
public class ObjectSrcDirective extends AbstractSrcDirective {

	/**
	 * The name of the directive
	 */
	public static final String NAME = "object-src";

	public ObjectSrcDirective() {
		super(ObjectSrcDirective.NAME);
	}

	/**
	 * adds the value 'none' to the directive
	 * @return a reference to this object
	 */
	public ObjectSrcDirective addNone() {
		addDirectiveValue(Validator.SRC_KEY_NONE);
		return this;
	}

	/**
	 * adds the value 'self' to the directive
	 * @return a reference to this object
	 */
	public ObjectSrcDirective addSelf() {
		addDirectiveValue(Validator.SRC_KEY_SELF);
		return this;
	}

	/**
	 * adds the given value to the directive
	 * @param source the src-list attribute to add to the directive
	 * @return a reference to this object
	 */
	public ObjectSrcDirective addSource(String source) {
		addDirectiveValue(source);
		return this;
	}
}
