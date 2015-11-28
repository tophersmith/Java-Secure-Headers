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
package securityheaders.impl;

import java.util.ArrayList;
import java.util.List;

import securityheaders.util.InvalidHeaderException;

public abstract class AbstractHeader {
	private final String primaryHeaderName;
	private final List<String> headerNames;

	protected AbstractHeader(String primaryName, String... altNames) {
		this.primaryHeaderName = primaryName;
		if (altNames != null && altNames.length > 0) {
			this.headerNames = new ArrayList<String>(altNames.length + 1);
			for (int i = 0; i < altNames.length; i++) {
				String altName = altNames[i];
				if (altName != null) {
					addHeaderName(altName);
				}
			}
		} else {
			this.headerNames = new ArrayList<String>(1);
		}
		addHeaderName(primaryName);
	}

	private void addHeaderName(String name) {
		if (!this.headerNames.contains(name)) {
			this.headerNames.add(name);
		}
	}

	public String getPrimaryHeaderName() {
		return this.primaryHeaderName;
	}

	public List<String> getHeaderNames() {
		return this.headerNames;
	}

	public abstract void validate() throws InvalidHeaderException;

	public abstract String buildHeaderValue();
}
