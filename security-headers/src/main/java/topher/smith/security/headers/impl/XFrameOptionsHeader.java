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

import org.apache.commons.validator.routines.UrlValidator;

import topher.smith.security.headers.util.InvalidHeaderException;

/**
 * The X-Frame-Options header is used in response headers to configure 
 * which sites may frame this response's resource.
 * This defends against UI Redress attaks such as Clickjacking
 * 
 * @author Chris Smith
 *
 */
public class XFrameOptionsHeader extends AbstractHeader {
	private static final String PRIMARY_HEADER_NAME = "X-Frame-Options";
	private static final String DENY = "DENY";
	private static final String SAMEORIGIN = "SAMEORIGIN";
	private static final String ALLOWFROM = "ALLOW-FROM";

	private String framingPolicy = XFrameOptionsHeader.SAMEORIGIN;
	private String origin = null;
	private final UrlValidator validator = new UrlValidator(new String[]{"http", "https"});

	/**
	 * Constructs a new X-Frame-Options Header object
	 * By default, sets the header to SAMEORIGIN
	 */
	public XFrameOptionsHeader() {
		super(XFrameOptionsHeader.PRIMARY_HEADER_NAME);
	}

	/**
	 * sets the header to DENY
	 * @return a reference to this object
	 */
	public XFrameOptionsHeader setDeny() {
		this.framingPolicy = XFrameOptionsHeader.DENY;
		this.origin = null;
		return this;
	}

	/**
	 * sets the header to SAMEORIGIN
	 * @return a reference to this object
	 */
	public XFrameOptionsHeader setSameOrigin() {
		this.framingPolicy = XFrameOptionsHeader.SAMEORIGIN;
		this.origin = null;
		return this;
	}

	/**
	 * sets the header to ALLOW-FROM with the given parameter
	 * @param origin the URL of the allowed framers
	 * @return a reference to this object
	 */
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

	/**
	 * If Allow-From is used, a valid origin must also be set
	 */
	@Override
	public void validate() throws InvalidHeaderException {
		if (this.framingPolicy.equals(XFrameOptionsHeader.ALLOWFROM)){
			if(!this.validator.isValid(this.origin)){
				throw new InvalidHeaderException("When using Allow-From, a valid origin must be set");
			}
		}
	}
}
