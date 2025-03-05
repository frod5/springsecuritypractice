package io.security.springsecuritymaster.security.util;

import jakarta.servlet.http.HttpServletRequest;

public class WebUtil {

	private static final String XML_HTTP_REQUEST = "XMLHttpRequest";
	private static final String X_REQUESTED_WITH = "X-Requested-With";
	private static final String CONTENT_TYPE = "Content-Type";
	private static final String CONTENT_TYPE_JSON = "application/json";

	public static boolean isAjax(HttpServletRequest request) {
		return XML_HTTP_REQUEST.equals(request.getHeader(X_REQUESTED_WITH));
	}

	public static boolean isContentTypeJson(HttpServletRequest request) {
		return CONTENT_TYPE_JSON.contains(request.getHeader(CONTENT_TYPE));
	}
}
