package tophersmith.security.headers.util;

import java.nio.file.InvalidPathException;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The Validator class contains multiple helper methods to verify that
 * given values conform to certain characteristics
 * 
 * @author Chris Smith
 *
 */
public class Validator{

	/**
	 * src-list describes a wildcard as: *
	 */
	public static final String SRC_WILDCARD = "*";

	/**
	 * src-list describes a wildcard as: 'none'
	 */
	public static final String SRC_KEY_NONE = "'none'";
	
	/**
	 * src-list describes a wildcard as: 'self'
	 */
	public static final String SRC_KEY_SELF = "'self'";
	
	/**
	 * src-list describes a wildcard as: 'unsafe-inline'
	 */
	public static final String SRC_UNSAFE_INLINE = "'unsafe-inline'";
	
	/**
	 * src-list describes a wildcard as: 'unsafe-eval'
	 */
	public static final String SRC_UNSAFE_EVAL = "'unsafe-eval'";
	
	//these characters may not exist in any directive value
	static final String[] ILLEGAL_SRC_CHARS = { " ", ";", "," };

	private static final int PORT_MAX = 65535;
	private static final int PORT_MIN = 0;

	// 1 letter plus optional letters, digits, +, -, or .
	private static final String SCHEME_PART = "[a-zA-Z]{1}(?:[a-zA-Z0-9\\+\\-\\.])*";

	// * OR Optional *. plus 1 or more letters/digits plus optional . plus 1 or more letters/digits
	private static final String HOST_PART = "(?:[*])|(?:(?:\\*\\.)?[A-Za-z0-9\\-]{1}(?:[\\.]?[A-Za-z0-9\\-])*)";

	// : followed by either 1 or more digits or *
	private static final String PORT_PART = ":(?:[\\d]+|\\*)";

	// a slash optionally followed by a non-slash character followed by any characters
	//private static final String PATH_PART = "(?:\\/[^?#]*)+";
	private static final String PATH_PART = "(?:\\/[-\\w:@&?=+,.!/~*'%$_;\\(\\)]*)";

	//host-source definition
	private static final Pattern HOST_SOURCE = Pattern.compile("^" + // match start of string
			"(" + SCHEME_PART + ":\\/\\/)?" + // scheme-part is optional
			"(" + HOST_PART + ")?" + // host-part is required
			"(" + PORT_PART + ")?" + // port-part is optional
			"(" + PATH_PART + ")?" + // path-part is optional
			"$");//match end of string

	//scheme-source definition
	private static final Pattern SCHEME_SOURCE = Pattern.compile("^" + SCHEME_PART + ":$");

	
	//base64 definition
	private static final Pattern BASE64 = Pattern.compile("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$");
	
	public static boolean hasValidCharacters(String value){
		if(value == null){
			return false;
		}
		for (int i = 0; i < ILLEGAL_SRC_CHARS.length; i++) {
			if (value.contains(ILLEGAL_SRC_CHARS[i])) {
				return false;
			}
		}
		return true;
	}
	
	
	public static boolean isValidSrcKeyword(String value){
		return  value != null && 
				( value.equals(SRC_KEY_SELF) || 
				  value.equals(SRC_KEY_NONE) );
	}
	
	
	public static boolean isValidUnsafeKeyword(String value){
		return  value != null && 
				( value.equals(SRC_UNSAFE_EVAL) || 
				  value.equals(SRC_UNSAFE_INLINE) );
	}
	
	
	public static boolean isValidSchemeSource(String value) {
		if (value == null) {
			return false;
		}

		Matcher urlMatcher = SCHEME_SOURCE.matcher(value);
		if(!urlMatcher.matches()) {
			return false;
		}
		
		return true;
	}

	
	public static boolean isValidHostSource(String value) {
		if (value == null) {
			return false;
		}

		Matcher urlMatcher = HOST_SOURCE.matcher(value);
		if(!urlMatcher.matches()) {
			return false;
		}
		
		String port = urlMatcher.group(3);
		String path = urlMatcher.group(4);
		
		try{
			if(port != null){
				if(port.startsWith(":")){
					port = port.substring(1, port.length());
				}
				int prt = Integer.parseInt(port);
				/*
				 * PORT MIN will not be hit as the regex will catch it, kept for
				 * completeness and future-proofing
				 */
				
				if(prt < PORT_MIN || prt > PORT_MAX){ 
					return false;
				}
			}
		}catch(NumberFormatException e){
			//Also should not be possible to hit due to the regex
			return false;
		}
		
		try{
			if(path != null){
				Paths.get(path);
			}
		}catch(InvalidPathException e){
			return false;
		}
		
		return true;
	}
	
	/**
	 * return true if the string could be a base64-encoded string 
	 * @param str a string to validate against
	 * @return true if the string could be base64 encoded
	 */
	public static boolean isBase64String(String str){
		return BASE64.matcher(str).find();
	}
}
