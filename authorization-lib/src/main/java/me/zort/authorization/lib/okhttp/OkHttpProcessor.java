package me.zort.authorization.lib.okhttp;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.squareup.okhttp.*;
import lombok.RequiredArgsConstructor;
import me.zort.authorization.lib.HttpProcessor;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.util.Map;

@RequiredArgsConstructor
public class OkHttpProcessor extends HttpProcessor {

    private final OkHttpClient client;
    private final JsonParser parser = new JsonParser();

    public OkHttpProcessor() {
        this(new OkHttpClient());
    }

    @Override
    public @Nullable JsonObject perform(String relativeUrl, String method, Map<String, String> headers, @Nullable JsonObject body) throws BadStatusException {
        method = method.toUpperCase();
        String absoluteUrl = getBaseUrl() + relativeUrl;
        Request.Builder requestBuilder = new Request.Builder().url(absoluteUrl);
        requestBuilder.header("Content-Type", "application/json");
        if (headers != null) {
            headers.forEach(requestBuilder::addHeader);
        }
        if (body != null) {
            requestBuilder.method(method, RequestBody.create(MediaType.parse("application/json"), body.toString()));
        }
        try {
            Response response = client.newCall(requestBuilder.build()).execute();
            if (response.code() != 200) {
                throw new BadStatusException(response.code());
            }
            try (ResponseBody responseBody = response.body()) {
                if (responseBody == null) {
                    return null;
                }
                return parser.parse(responseBody.string()).getAsJsonObject();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
