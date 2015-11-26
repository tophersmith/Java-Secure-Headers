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
