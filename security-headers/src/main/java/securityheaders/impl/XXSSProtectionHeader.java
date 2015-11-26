package securityheaders.impl;

import securityheaders.util.InvalidHeaderException;

public class XXSSProtectionHeader extends AbstractHeader {
	private static final String PRIMARY_HEADER_NAME = "X-Frame-Options";
	private static final String PROTECTION_ON = "1";
	private static final String PROTECTION_OFF = "0";
	private static final String BLOCK = "mode=block";

	private boolean protection = true;
	private boolean block = true;

	public XXSSProtectionHeader() {
		super(XXSSProtectionHeader.PRIMARY_HEADER_NAME);
	}

	public XXSSProtectionHeader enableProtection() {
		this.protection = true;
		return this;
	}

	public XXSSProtectionHeader disableProtection() {
		this.protection = false;
		return this;
	}

	public XXSSProtectionHeader enableBlock() {
		this.block = true;
		return this;
	}

	@Override
	public String buildHeaderValue() {
		String headerValue;
		if (this.protection) {
			if (this.block) {
				headerValue = new StringBuilder().append(XXSSProtectionHeader.PROTECTION_ON).append("; ")
						.append(XXSSProtectionHeader.BLOCK).toString();
			} else {
				headerValue = XXSSProtectionHeader.PROTECTION_ON;
			}
		} else {
			headerValue = XXSSProtectionHeader.PROTECTION_OFF;
		}

		return headerValue;
	}

	@Override
	public void validate() throws InvalidHeaderException {
		if (!this.protection && this.block) {
			throw new InvalidHeaderException("Cannot disabled X-XSS-Protection, but require mode=block");
		}
	}

}
