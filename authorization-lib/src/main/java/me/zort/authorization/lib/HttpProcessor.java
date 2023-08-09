package me.zort.authorization.lib;

import com.google.gson.JsonObject;
import lombok.Getter;
import org.jetbrains.annotations.Nullable;

import java.util.Map;

@Getter
public abstract class HttpProcessor {

    private String baseUrl = null;

    /**
     * Performs an HTTP request to provided **relative!** url and JSON body.
     * This method should return a JSON object representing response body and optionally throw
     * a {@link BadStatusException} if the status code is not 200.
     * <p>
     * Note that this request should construct the full URL using following code:
     * <pre>
     *     String fullUrl = getBaseUrl() + relativeUrl;
     * </pre>
     *
     * @param relativeUrl Relative URL to the base URL
     * @param method HTTP method to use
     * @param body JSON body to send (optional)
     * @return Response body
     * @throws BadStatusException When status code is not 200
     */
    @Nullable
    public abstract JsonObject perform(String relativeUrl, String method, Map<String, String> headers, @Nullable JsonObject body) throws BadStatusException;

    protected void setBaseUrl(String baseUrl) {
        if (this.baseUrl != null) {
            throw new RuntimeException("This HTTP processor has already been assigned.");
        }
        this.baseUrl = baseUrl;
    }

    public static class BadStatusException extends RuntimeException {
        public BadStatusException(int code) {
            super("Bad status code: " + code);
        }
    }

}
