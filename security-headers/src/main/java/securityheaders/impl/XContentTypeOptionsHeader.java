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

public class XContentTypeOptionsHeader extends AbstractHeader {

	private static final String PRIMARY_HEADER_NAME = "X-Content-Type-Options";
	private static final String NOSNIFF = "nosniff";

	public XContentTypeOptionsHeader() {
		super(XContentTypeOptionsHeader.PRIMARY_HEADER_NAME);
	}

	@Override
	public String buildHeaderValue() {
		return XContentTypeOptionsHeader.NOSNIFF;
	}

	@Override
	public void validate() throws InvalidHeaderException {
		// impossible to fail as the only value is nosniff and it is required
	}

}
