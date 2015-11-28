package securityheaders.util;

/**
 * InvalidHeaderException is thrown whenever a header is invalid for a supplied reason
 * @author Chris
 *
 */
public class InvalidHeaderException extends Exception {

	private static final long serialVersionUID = 3377827192680756116L;

	/**
	 * Construct an InvalidHeaderException with the given message
	 */
	public InvalidHeaderException(String message) {
		super(message);
	}
}
