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

public class XFrameOptionsHeader extends AbstractHeader {
	private static final String PRIMARY_HEADER_NAME = "X-Frame-Options";
	private static final String DENY = "DENY";
	private static final String SAMEORIGIN = "SAMEORIGIN";
	private static final String ALLOWFROM = "ALLOW-FROM";

	private String framingPolicy = XFrameOptionsHeader.SAMEORIGIN;
	private String origin = null;

	public XFrameOptionsHeader() {
		super(XFrameOptionsHeader.PRIMARY_HEADER_NAME);
	}

	public XFrameOptionsHeader setDeny() {
		this.framingPolicy = XFrameOptionsHeader.DENY;
		this.origin = null;
		return this;
	}

	public XFrameOptionsHeader setSameOrigin() {
		this.framingPolicy = XFrameOptionsHeader.SAMEORIGIN;
		this.origin = null;
		return this;
	}

	public XFrameOptionsHeader setAllowFrom(String origin) {
		this.framingPolicy = XFrameOptionsHeader.ALLOWFROM;
		this.origin = origin;
		return this;
	}

	@Override
	public String buildHeaderValue() {
		String headerValue;
		if (this.origin == null) {
			headerValue = this.framingPolicy;
		} else {
			headerValue = new StringBuilder().append(this.framingPolicy).append(" ").append(this.origin).toString();
		}
		return headerValue;
	}

	@Override
	public void validate() throws InvalidHeaderException {
		if (this.framingPolicy.equals(XFrameOptionsHeader.ALLOWFROM)
				&& (this.origin == null || this.origin.isEmpty())) {
			throw new InvalidHeaderException("When using Allow-From, a valid origin must be set");
		}
	}

}
