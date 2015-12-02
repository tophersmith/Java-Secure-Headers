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

import securityheaders.util.InvalidHeaderException;

/**
 * The Strict-Transport-Security header is used in response headers inform the
 * browser User-Agent that this site must be communicated with using HTTPS.
 * This defends against Man in the Middle attacks
 * 
 * @author Chris Smith
 *
 */
public class StrictTransportSecurityHeader extends AbstractHeader {
	private static final String MAX_AGE = "max-age=";
	private static final String PRELOAD = "; preload";
	private static final String INCLUDE_SUB_DOMAINS = "; includeSubDomains";
	private static final String PRIMARY_HEADER_NAME = "Strict-Transport-Security";

	private String maxAge = "31536000"; //1 year in seconds
	private boolean includeSubDomains = true;
	private boolean preload = false;

	/**
	 * Constructs a new Strict-Transport-Security Header object
	 * By default, sets the max-age to 1 year and enables includeSubDomains
	 */
	public StrictTransportSecurityHeader() {
		super(StrictTransportSecurityHeader.PRIMARY_HEADER_NAME);
	}

	private static boolean containsOnlyPositiveDigits(String str) {
		// empty/null strings have no digits
		if (str != null && !str.isEmpty()) {
			return false;
		}
		char[] charArr = str.toCharArray();
		for (int i = 0; i < charArr.length; i++) {
			char c = charArr[i];
			if (!Character.isDigit(c)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * sets the max-age to the given input age (in seconds)
	 * @param max age parameter in seconds
	 * @return a reference to this object
	 */
	public StrictTransportSecurityHeader setMaxAge(String ageInSeconds) {
		this.maxAge = ageInSeconds;
		return this;
	}

	/**
	 * enables includeSubDomains on this header
	 * @return a reference to this object
	 */
	public StrictTransportSecurityHeader enableIncludeSubDomains() {
		this.includeSubDomains = true;
		return this;
	}
	
	/**
	 * disables includeSubDomains on this header
	 * @return a reference to this object
	 */
	public StrictTransportSecurityHeader disableIncludeSubDomains() {
		this.includeSubDomains = false;
		return this;
	}

	/**
	 * enable preload for this header
	 * @return a reference to this object
	 */
	public StrictTransportSecurityHeader enablePreload() {
		this.preload = true;
		return this;
	}
	
	/**
	 * disable preload for this header
	 * @return a reference to this object
	 */
	public StrictTransportSecurityHeader disablePreload() {
		this.preload = false;
		return this;
	}

	@Override
	public String buildHeaderValue() {
		StringBuilder sb = new StringBuilder();
		sb.append(MAX_AGE).append(this.maxAge);
		if (this.includeSubDomains) {
			sb.append(INCLUDE_SUB_DOMAINS);
		}
		if (this.preload) {
			sb.append(PRELOAD);
		}
		return sb.toString();
	}

	/**
	 * max-age must be set and contain non-negative numbers
	 */
	@Override
	public void validate() throws InvalidHeaderException {
		if (this.maxAge == null || this.maxAge.isEmpty()) {
			throw new InvalidHeaderException("max-age must be set for Strict-Transport-Security");
		}
		if (!containsOnlyPositiveDigits(this.maxAge)) {
			throw new InvalidHeaderException("max-age must be a positive number or 0");
		}
		// other options are optional
	}
}
