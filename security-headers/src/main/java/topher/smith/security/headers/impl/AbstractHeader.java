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
package topher.smith.security.headers.impl;

import topher.smith.security.headers.util.InvalidHeaderException;

/**
 * Base Abstraction for all headers
 * 
 * @author Chris Smith
 *
 */
public abstract class AbstractHeader {
	private final String headerName;

	/**
	 * Base abstraction to set up header names
	 * 
	 * @param primaryName Required name of the header
	 * @param altNames Optional name(s) of the header (e.g. for experimental headers)
	 */
	protected AbstractHeader(String headerName) {
		this.headerName = headerName;
	}

	/**
	 * @return required header name
	 */
	public String getHeaderName() {
		return this.headerName;
	}

	/**
	 * ensure all header values are set correctly individually or
	 * in combination. Assumed valid if no exception is thrown.
	 * 
	 * @throws InvalidHeaderException if <u>any</u> validate error occurs
	 */
	public abstract void validate() throws InvalidHeaderException;

	/**
	 * Constructs a String representation of the value of this header.
	 * Does not validate.
	 * @return a String representation of this header's value
	 */
	public abstract String buildHeaderValue();
}
