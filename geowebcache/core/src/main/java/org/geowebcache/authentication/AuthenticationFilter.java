package org.geowebcache.authentication;

import javax.servlet.http.HttpServletRequest;

public interface AuthenticationFilter {

    public boolean checkRequest(HttpServletRequest req);
}
