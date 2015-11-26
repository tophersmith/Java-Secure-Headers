package securityheaders;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import securityheaders.impl.AbstractHeader;
import securityheaders.util.InvalidHeaderException;

public class SecurityHeaders {

	private final List<AbstractHeader> headers;
	private static final Character[] ILLEGAL_CHARS = new Character[] { '\r', '\n' };

	public SecurityHeaders() {
		this.headers = new ArrayList<AbstractHeader>();
	}

	public SecurityHeaders addHeader(AbstractHeader header) {
		this.headers.add(header);
		return this;
	}

	public List<InvalidHeaderException> validateAllHeaders() {
		List<InvalidHeaderException> exceptions = null;
		for (int i = 0; i < this.headers.size(); i++) {
			AbstractHeader header = this.headers.get(i);
			try {
				header.validate();
			} catch (InvalidHeaderException e) {
				if (exceptions == null) {
					exceptions = new ArrayList<InvalidHeaderException>();
				}
				exceptions.add(e);
			}
		}
		return exceptions;
	}

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

	public void addHeadersToResponse(HttpServletResponse response, List<String> headersList)
			throws InvalidHeaderException {
		for (int i = 0; i < headersList.size(); i++) {
			String[] header = headersList.get(i).split(":");
			if (header.length != 2) {
				throw new InvalidHeaderException("Given headers do not contain a key and value");
			}
			response.addHeader(sanitizeHeaderData(header[0].trim()), sanitizeHeaderData(header[1].trim()));
		}
	}

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

	private static boolean charContains(char target, Character... test) {
		for (int i = 0; i < test.length; i++) {
			if (test[i].equals(target)) {
				return true;
			}
		}
		return false;
	}

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

	private static String sanitizeHeaderData(String data) {
		return remove(data, SecurityHeaders.ILLEGAL_CHARS);
	}
}
