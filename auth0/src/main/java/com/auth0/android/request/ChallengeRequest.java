package com.auth0.android.request;

import android.support.annotation.NonNull;

import com.auth0.android.authentication.AuthenticationException;
import com.auth0.android.result.Challenge;

import java.util.Map;

public interface ChallengeRequest extends Request<Challenge, AuthenticationException> {

    /**
     * Add all entries of the map as parameters of this request
     *
     * @param parameters to be added to the request
     * @return itself
     */
    @NonNull
    ChallengeRequest addChallengeParameters(@NonNull Map<String, Object> parameters);
}
