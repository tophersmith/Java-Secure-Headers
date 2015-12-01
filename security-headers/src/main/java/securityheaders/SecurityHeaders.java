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
package securityheaders;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import securityheaders.impl.AbstractHeader;
import securityheaders.util.InvalidHeaderException;

/**
 * SecurityHeaders implements the following Security-related headers:
 * <ul>
 * <li>Content-Security-Policy</li>
 * <li>Strict-Transport-Security</li>
 * <li>X-Content-Type-Options</li>
 * <li>X-Frame-Options</li>
 * <li>X-XSS-Protection</li>
 * </ul>
 * It also manages adding the Headers to a Response object.
 * 
 * 
 * @author Chris Smith
 *
 */
public class SecurityHeaders {

	private final List<AbstractHeader> headers;
	private static final Character[] ILLEGAL_CHARS = new Character[] { '\r', '\n' };

	public SecurityHeaders() {
		this.headers = new ArrayList<AbstractHeader>();
	}

	/**
	 * adds the given header to this object
	 * @param header a Security Header
	 * @return a reference to this object
	 */
	public SecurityHeaders addHeader(AbstractHeader header) {
		this.headers.add(header);
		return this;
	}

	/**
	 * Validates each header according to its own validation requirements
	 * @return a list of exceptions or null, if no exceptions occurred
	 */
	public List<String> validateAllHeaders() {
		List<String> exceptions = null;
		for (int i = 0; i < this.headers.size(); i++) {
			AbstractHeader header = this.headers.get(i);
			try {
				header.validate();
			} catch (InvalidHeaderException e) {
				if (exceptions == null) {
					exceptions = new ArrayList<String>();
				}
				exceptions.add(e.getMessage());
			}
		}
		return exceptions;
	}

	/**
	 * Dispatch to each header to have it construct its own complete header line
	 * <br/>
	 * e.g. Header-Name: HeaderValue(s)
	 * @return a list of Strings containing the full header line
	 */
	public List<String> buildHeaders() {
		List<String> headers = new ArrayList<String>();
		for (int i = 0; i < this.headers.size(); i++) {
			AbstractHeader header = this.headers.get(i);
			List<String> headerNames = header.getHeaderNames();
			String headerValue = header.buildHeaderValue();
			for (int j = 0; j < headerNames.size(); j++) {
				String headerName = headerNames.get(j);
				String fullHeader = new StringBuilder().append(headerName).append(": ").append(headerValue).toString();
				headers.add(fullHeader);
			}
		}
		return headers;
	}

	/**
	 * Given a ServletResponse and a List of header lines, add the supplied
	 * headers to the supplied Response
	 * @param response a response object to have headers attached 
	 * @param headersList List of header lines
	 * @throws InvalidHeaderException if a header does not have a key and value
	 */
	public static void addHeadersToResponse(HttpServletResponse response, List<String> headersList)
			throws InvalidHeaderException {
		for (int i = 0; i < headersList.size(); i++) {
			String[] header = headersList.get(i).split(":");
			if (header.length != 2) {
				throw new InvalidHeaderException("Given headers do not contain a key and value");
			}
			response.addHeader(sanitizeHeaderData(header[0].trim()), sanitizeHeaderData(header[1].trim()));
		}
	}

	/**
	 * using the headers in this object, add the defined security headers to
	 * the given response object
	 * @param response a response object to have headers attached
	 */
	public void addHeadersToResponse(HttpServletResponse response) {
		for (int i = 0; i < this.headers.size(); i++) {
			AbstractHeader header = this.headers.get(i);
			List<String> headerNames = header.getHeaderNames();
			String headerValue = header.buildHeaderValue();
			for (int j = 0; j < headerNames.size(); j++) {
				String headerName = headerNames.get(j);
				response.addHeader(headerName, sanitizeHeaderData(headerValue));
			}
		}
	}

	/**
	 * Given a ServletResponse and a List of header lines, set the supplied
	 * headers to the supplied Response
	 * @param response a response object to have headers attached 
	 * @param headersList List of header lines
	 * @throws InvalidHeaderException if a header does not have a key and value
	 */
	public void setHeadersOnResponse(HttpServletResponse response, List<String> headersList)
			throws InvalidHeaderException {
		for (int i = 0; i < headersList.size(); i++) {
			String[] header = headersList.get(i).split(":");
			if (header.length != 2) {
				throw new InvalidHeaderException("Given headers do not contain a key and value");
			}
			response.setHeader(sanitizeHeaderData(header[0].trim()), sanitizeHeaderData(header[1].trim()));
		}
	}

	/**
	 * using the headers in this object, set the defined security headers to
	 * the given response object
	 * @param response a response object to have headers attached
	 */
	public void setHeadersOnResponse(HttpServletResponse response) {
		for (int i = 0; i < this.headers.size(); i++) {
			AbstractHeader header = this.headers.get(i);
			List<String> headerNames = header.getHeaderNames();
			String headerValue = header.buildHeaderValue();
			for (int j = 0; j < headerNames.size(); j++) {
				String headerName = headerNames.get(j);
				response.setHeader(headerName, sanitizeHeaderData(headerValue));
			}
		}
	}

	/**
	 * a helper method to see if a given target character is in an array of 
	 * characters
	 */
	private static boolean charContains(char target, Character... test) {
		for (int i = 0; i < test.length; i++) {
			if (test[i].equals(target)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * given a String and an array of characters to remove from the String,
	 * return a String with the specified characters removed
	 */
	private static String remove(String text, Character... characters) {
		StringBuilder sb = new StringBuilder(text.length());
		for (int i = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			if (!charContains(c, characters)) {
				sb.append(c);
			}
		}
		return sb.toString();
	}

	/**
	 * removes Illegal header characters from the supplied String data 
	 */
	private static String sanitizeHeaderData(String data) {
		return remove(data, SecurityHeaders.ILLEGAL_CHARS);
	}
}
