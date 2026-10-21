package com.identvia.core

import kotlinx.serialization.json.JsonObject

/** The parts of `/.well-known/openid-configuration` the SDK uses. */
data class ProviderMetadata(
    val issuer: String,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val userinfoEndpoint: String?,
    val jwksUri: String,
    val revocationEndpoint: String?,
    val endSessionEndpoint: String?,
    val codeChallengeMethodsSupported: List<String>?,
    val grantTypesSupported: List<String>?,
    val authorizationResponseIssParameterSupported: Boolean,
    /** Stage 5 (server 2026-10-21_5+): RFC 9396 types such as `agent_task`. */
    val authorizationDetailsTypesSupported: List<String>?,
) {
    companion object {
        fun from(o: JsonObject): ProviderMetadata? {
            return ProviderMetadata(
                issuer = o.str("issuer") ?: return null,
                authorizationEndpoint = o.str("authorization_endpoint") ?: return null,
                tokenEndpoint = o.str("token_endpoint") ?: return null,
                userinfoEndpoint = o.str("userinfo_endpoint"),
                jwksUri = o.str("jwks_uri") ?: return null,
                revocationEndpoint = o.str("revocation_endpoint"),
                endSessionEndpoint = o.str("end_session_endpoint"),
                codeChallengeMethodsSupported = o.strList("code_challenge_methods_supported"),
                grantTypesSupported = o.strList("grant_types_supported"),
                authorizationResponseIssParameterSupported = o.bool("authorization_response_iss_parameter_supported") == true,
                authorizationDetailsTypesSupported = o.strList("authorization_details_types_supported"),
            )
        }
    }
}
