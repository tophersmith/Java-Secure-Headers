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
