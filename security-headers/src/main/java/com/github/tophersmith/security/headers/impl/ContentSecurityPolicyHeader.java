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
package com.github.tophersmith.security.headers.impl;

import java.util.List;

import com.github.tophersmith.security.headers.csp.ContentSecurityPolicy;
import com.github.tophersmith.security.headers.util.InvalidHeaderException;

/**
 * The Content-Security-Policy header is used in response headers to inform 
 * the User-Agent from where certain kinds of resources may be loaded.
 * This defends against XSS, UI Redress, and many other kinds of attacks
 * 
 * @author Chris Smith
 *
 */
public class ContentSecurityPolicyHeader extends AbstractHeader {

	/**
	 * Defines the available header names for CSP
	 * Defines both the standard(violation mode) header as well as the 
	 * report only header
	 * 
	 * @author Chris Smith
	 *
	 */
	public static enum CSPHeaderName {
		CSP("Content-Security-Policy", "Content-Security-Policy-Report-Only"), 
		XCSP("X-Content-Security-Policy", "X-Content-Security-Policy-Report-Only"), 
		WEBKIT("X-Webkit-CSP", "X-Webkit-CSP-Report-Only"),
		;
		
		private final String primary;
		private final String report;

		private CSPHeaderName(String primary, String reportOnly) {
			this.primary = primary;
			this.report = reportOnly;
		}

		String getPrimaryName() {
			return this.primary;
		}

		String getReportName() {
			return this.report;
		}
	}

	private static final String LINE_SEPERATOR = System.lineSeparator();
	private boolean reduce = false;
	private ContentSecurityPolicy csp = null;

	/**
	 * Constructs a new Content-Security-Policy Header object
	 * <b>Does not</b> configure a CSP by default, and does not enable 
	 * report-only mode, also does not reduce
	 * @param headerName which CSPHeaderName type this should use 
	 */
	public ContentSecurityPolicyHeader(CSPHeaderName headerName) {
		this(headerName, false);
	}

	/**
	 * Constructs a new Content-Security-Policy Header object
	 * <b>Does not</b> configure a CSP by default
	 * @param headerName which CSPHeaderName type this should use
	 * @param reportOnly sets whether to use the reporting header or not 
	 */
	public ContentSecurityPolicyHeader(CSPHeaderName headerName, boolean reportOnly) {
		super(reportOnly ? headerName.getReportName() : headerName.getPrimaryName());
	}

	/**
	 * Sets Content-Security-Policy to reduce the policy
	 * @param reduce true if CSP should be minified
	 * @return a reference to this object
	 */
	public ContentSecurityPolicyHeader setReduce(boolean reduce) {
		this.reduce = reduce;
		return this;
	}

	/**
	 * Assign a ContentSecurityPolicy object to this header
	 * @param policy the configured CSP
	 * @return a reference to this object
	 */
	public ContentSecurityPolicyHeader setPolicy(ContentSecurityPolicy policy) {
		this.csp = policy;
		return this;
	}

	@Override
	public String buildHeaderValue() {
		String value = null;
		if (this.csp != null) {
			if (this.reduce) {
				this.csp.reduce();
			}
			value = this.csp.build();
		}
		return value;
	}

	/**
	 * validation is dispatched to {@link ContentSecurityPolicy#isValid()}
	 */
	@Override
	public void validate() throws InvalidHeaderException {
		if(this.csp == null){
			throw new InvalidHeaderException("ContentSecurityPolicy must be set on the header");
		}
		this.csp.resetValidationReport();
		if (!this.csp.isValid()) {
			StringBuilder sb = new StringBuilder();
			sb.append("ContentSecurityPolicyHeader is invalid:").append(ContentSecurityPolicyHeader.LINE_SEPERATOR);
			List<String> reports = this.csp.getValidationErrorReports();
			for (int i = 0; i < reports.size(); i++) {
				sb.append(reports.get(i)).append(ContentSecurityPolicyHeader.LINE_SEPERATOR);
			}
			throw new InvalidHeaderException(sb.toString());
		}
	}
	
	/**
	 * return all validation errors. Must have called validate already
	 */
	public List<String> getValidationErrors(){
		if(this.csp != null){
			return this.csp.getValidationErrorReports();
		}
		return null;
	}
	
	/**
	 * return all validation warnings. Must have called validate already
	 */
	public List<String> getValidationWarnings(){
		if(this.csp != null){
			return this.csp.getValidationWarningReports();
		}
		return null;
	}
}
