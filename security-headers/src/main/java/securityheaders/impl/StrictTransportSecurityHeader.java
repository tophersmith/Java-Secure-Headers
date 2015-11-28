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

public class StrictTransportSecurityHeader extends AbstractHeader {

	private static final String PRIMARY_HEADER_NAME = "Strict-Transport-Security";

	private String maxAge = null;
	private boolean includeSubDomains = false;
	private boolean preload = false;

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

	public StrictTransportSecurityHeader addMaxAge(String ageInSeconds) {
		this.maxAge = ageInSeconds;
		return this;
	}

	public StrictTransportSecurityHeader addIncludeSubDomains() {
		this.includeSubDomains = true;
		return this;
	}

	public StrictTransportSecurityHeader addPreload() {
		this.includeSubDomains = true;
		return this;
	}

	@Override
	public String buildHeaderValue() {
		StringBuilder sb = new StringBuilder();

		sb.append("max-age=").append(this.maxAge);

		if (this.includeSubDomains) {
			sb.append("; includeSubDomains");
		}

		if (this.preload) {
			sb.append("; preload");
		}

		return sb.toString();
	}

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
