package com.auth0.android.request.internal;

import android.support.annotation.NonNull;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.request.ChallengeRequest;
import com.auth0.android.result.Challenge;
import com.google.gson.Gson;
import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.OkHttpClient;

import java.util.HashMap;
import java.util.Map;

class BaseChallengeRequest extends SimpleRequest<Challenge, AuthenticationException> implements ChallengeRequest {
    public BaseChallengeRequest(HttpUrl url, OkHttpClient client, Gson gson, String httpMethod) {
        super(url, client, gson, httpMethod, Challenge.class, new AuthenticationErrorBuilder());
    }

    @NonNull
    @Override
    public ChallengeRequest addChallengeParameters(@NonNull Map<String, Object> parameters) {
        final HashMap<String, Object> params = new HashMap<>(parameters);
        addParameters(params);
        return this;
    }
}
