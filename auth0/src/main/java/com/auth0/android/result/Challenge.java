package com.auth0.android.result;

import android.support.annotation.Nullable;

import com.google.gson.annotations.SerializedName;

public class Challenge {
    @SerializedName("challenge_type")
    private final String challengeType;

    @SerializedName("oob_code")
    private final String oobCode;

    @SerializedName("binding_method")
    private final String bindingMethod;

    public Challenge(@Nullable String challengeType, @Nullable String oobCode, @Nullable String bindingMethod) {
        this.challengeType = challengeType;
        this.oobCode = oobCode;
        this.bindingMethod = bindingMethod;
    }

    @Nullable
    public String getChallengeType() {
        return challengeType;
    }

    @Nullable
    public String getOobCode() {
        return oobCode;
    }

    @Nullable
    public String getBindingMethod() {
        return bindingMethod;
    }
}
