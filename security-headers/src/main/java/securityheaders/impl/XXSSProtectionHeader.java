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

import java.net.MalformedURLException;
import java.net.URL;

import securityheaders.util.InvalidHeaderException;

/**
 * The X-XSS-Protection header is used in response headers to require browser 
 * User Agents to enable reflective XSS protection. 
 * This defends the application against some XSS attacks.
 * 
 * @author Chris Smith
 *
 */
public class XXSSProtectionHeader extends AbstractHeader {
	private static final String PRIMARY_HEADER_NAME = "X-Frame-Options";
	private static final String PROTECTION_ON = "1";
	private static final String PROTECTION_OFF = "0";
	private static final String BLOCK = "mode=block";
	private static final String REPORT = "report=";

	private boolean protection = true;
	private boolean block = true;
	private String reportUrl = null;
	
	/**
	 * Constructs a new X-XSS-Protection Header object
	 * By default, builds X-XSS-Protection: 1; mode=block
	 * which enables the protection and requires the user 
	 * agent to block attacks (rather than try to filter)
	 */
	public XXSSProtectionHeader() {
		super(XXSSProtectionHeader.PRIMARY_HEADER_NAME);
	}

	/**
	 * Turns X-XSS protection on
	 * @return a reference to this object
	 */
	public XXSSProtectionHeader enableProtection() {
		this.protection = true;
		return this;
	}
	
	/**
	 * Turns X-XSS protection off
	 * @return a reference to this object
	 */
	public XXSSProtectionHeader disableProtection() {
		this.protection = false;
		return this;
	}

	/**
	 * Enables mode=block protection
	 * @return a reference to this object
	 */
	public XXSSProtectionHeader enableBlock() {
		this.block = true;
		return this;
	}
	
	/**
	 * Disables mode=block protection
	 * @return a reference to this object
	 */
	public XXSSProtectionHeader disableBlock() {
		this.block = false;
		return this;
	}
	
	/**
	 * Add (or replace) report URL. Only for Chrome/Webkit
	 * @param url 
	 * @return
	 */
	public XXSSProtectionHeader addReportURL(String url){
		this.reportUrl = url;
		return this;
	}
	
	@Override
	public String buildHeaderValue() {
		String headerValue;
		if (this.protection) {
			StringBuilder sb = new StringBuilder();
			sb.append(XXSSProtectionHeader.PROTECTION_ON);
			if (this.block) {
				sb.append("; ").append(XXSSProtectionHeader.BLOCK);
			}
			if (this.reportUrl != null){
				sb.append(": ").append(XXSSProtectionHeader.REPORT).append(this.reportUrl);
			}
			headerValue = sb.toString();
		} else {
			headerValue = XXSSProtectionHeader.PROTECTION_OFF;
		}
		return headerValue;
	}

	@Override
	public void validate() throws InvalidHeaderException {
		if(this.reportUrl != null){
			try {
				new URL(this.reportUrl);
			} catch (MalformedURLException e) {
				throw new InvalidHeaderException("Report url is not a valid URL");
			}
		}
		if (!this.protection) {
			if(this.block){
				throw new InvalidHeaderException("Cannot disable X-XSS-Protection, but require mode=block");
			} else if(this.reportUrl != null){
				throw new InvalidHeaderException("Cannot disable X-XSS-Protection, but enable reporting");
			}
		}
	}
}
