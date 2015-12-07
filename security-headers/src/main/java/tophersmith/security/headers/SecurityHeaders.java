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
package tophersmith.security.headers;

import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;

import tophersmith.security.headers.impl.AbstractHeader;
import tophersmith.security.headers.util.InvalidHeaderException;

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
	public List<String> buildHeaderLines() {
		List<String> headers = new ArrayList<String>();
		for (int i = 0; i < this.headers.size(); i++) {
			AbstractHeader header = this.headers.get(i);
			String headerName = header.getHeaderName();
			String headerValue = header.buildHeaderValue();
			String fullHeader = new StringBuilder().append(headerName).append(": ").append(headerValue).toString();
			headers.add(sanitizeHeaderData(fullHeader));
		}
		return headers;
	}
	
	/**
	 * Construct a list of header names and values for each attached Header
	 * 
	 * @return a list of header names and values
	 */
	public List<Entry<String,String>> buildHeaders(){
		List<Entry<String, String>> headers = new ArrayList<Entry<String,String>>();
		for (int i = 0; i < this.headers.size(); i++) {
			AbstractHeader header = this.headers.get(i);
			String headerName = header.getHeaderName();
			String headerValue = header.buildHeaderValue();
			headers.add(new SimpleEntry<String,String>(
					sanitizeHeaderData(headerName), sanitizeHeaderData(headerValue)));
		}
		return headers;
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
