package org.geowebcache.authentication;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import javax.servlet.http.HttpServletRequest;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.util.EntityUtils;

public class SmallMapAuthenticationFilter implements AuthenticationFilter {

    private static Log log =
            LogFactory.getLog(org.geowebcache.authentication.SmallMapAuthenticationFilter.class);

    private final String url;

    private final String httpUsername;

    private final String httpPassword;

    private Lock lock = new ReentrantLock();

    ConcurrentHashMap<String, Authorization> authorizations =
            new ConcurrentHashMap<String, Authorization>(100);

    public SmallMapAuthenticationFilter(String url) {
        this.url = url;
        this.httpPassword = null;
        this.httpUsername = null;
    }

    public SmallMapAuthenticationFilter(String url, String httpUsername, String httpPassword) {
        this.url = url;
        this.httpUsername = httpUsername;
        this.httpPassword = httpPassword;
    }

    public boolean checkRequest(HttpServletRequest req) {

        // log.error("Foo: checkRequest");

        String token = req.getHeader("Cookie");

        // log.error("Foo: checkRequest token: " + token);

        if (token == null) {
            return false;
        }

        Authorization auth = authorizations.get(token);
        // log.error(auth);

        if (auth != null) {
            // log.error(auth.expiration);
            // log.error(auth.authorized);

            if (auth.expiration > System.currentTimeMillis()) {
                return auth.authorized;
            } else {
                // It has expired, remove
                authorizations.remove(token);
            }
        }

        // We're here because it wasn't found
        lock.lock();
        try {
            // Try one more time, could have been fixed by now
            auth = authorizations.get(token);
            if (auth != null) {
                return auth.authorized;
            }

            // Get and insert the new one
            try {
                auth = getAuthorization(token);
            } catch (IOException e) {
                e.printStackTrace();
                auth = new Authorization(token, null, false);
            }

            authorizations.put(token, auth);
            return auth.authorized;
        } finally {
            lock.unlock();
        }
    }

    public Authorization getAuthorization(String token) throws IOException {

        // log.error("Foo: getAuth");

        // Set things up
        HttpClient httpClient = new DefaultHttpClient();
        HttpParams params = httpClient.getParams();
        HttpConnectionParams.setConnectionTimeout(params, 20000);
        HttpConnectionParams.setSoTimeout(params, 20000);
        HttpPost postMethod = new HttpPost(url);

        // log.error("Foo url: " + url);
        // log.error("Foo: " + token);

        List<NameValuePair> postParameters = new ArrayList<NameValuePair>(1);
        postParameters.add(new BasicNameValuePair("token", token));
        postMethod.setEntity(new UrlEncodedFormEntity(postParameters, "UTF-8"));

        if (this.httpUsername != null) {
            String encoding =
                    Base64.getEncoder()
                            .encodeToString((httpUsername + ":" + httpPassword).getBytes());
            postMethod.setHeader("Authorization", "Basic " + encoding);
        }

        // Do the request
        HttpResponse response = httpClient.execute(postMethod);

        // log.error("Foo: httpStatus ");
        // log.error(response.getStatusLine().getStatusCode());

        if (response.getStatusLine().getStatusCode() != 200) {
            return new Authorization(token, null, false);
        }

        // Decode the response and return object
        HttpEntity entity = response.getEntity();
        String responseBody = EntityUtils.toString(entity, "UTF-8");

        // log.error("Foo: response");
        // log.error(responseBody);

        JSONObject json = (JSONObject) JSONSerializer.toJSON(responseBody);
        Boolean authorized = (Boolean) json.get("auth");
        String name = (String) json.get("username");

        // log.error("Foo final: " + token + " " + name);
        // log.error(authorized);
        return new Authorization(token, name, authorized);
    }

    class Authorization {
        String key;

        String username;

        boolean authorized;

        long expiration;

        Authorization(String key, String username, boolean authorized) {
            this.key = key;
            this.username = username;
            this.authorized = authorized;

            if (authorized) {
                // Cache for one hour
                expiration = System.currentTimeMillis() + (3600 * 4) * 1000;
            } else {
                // Cache for one minute
                expiration = System.currentTimeMillis() + (60) * 1000;
            }
        }
    }
}
