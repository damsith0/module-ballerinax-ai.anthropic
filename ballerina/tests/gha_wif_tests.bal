// Live Workload Identity Federation tests with GitHub Actions as the identity provider. They run only in the
// "WIF GitHub Actions live test" workflow, which grants `id-token: write` and writes tests/Config.toml.

import ballerina/ai;
import ballerina/http;
import ballerina/io;
import ballerina/jwt;
import ballerina/os;
import ballerina/test;

configurable string ghaOrganizationId = "";
configurable string ghaFederationRuleId = "";
configurable string ghaServiceAccountId = "";
configurable string ghaWorkspaceId = "";

const GHA_ISSUER = "https://token.actions.githubusercontent.com";
const GHA_AUDIENCE = "https://api.anthropic.com";

isolated int ghaProviderCalls = 0;

// The identity token provider a user would write for GitHub Actions: it asks the runner's OIDC endpoint for a
// fresh JWT with the Anthropic audience.
isolated function githubActionsIdentityToken() returns string|error {
    lock {
        ghaProviderCalls += 1;
    }
    string requestUrl = os:getEnv("ACTIONS_ID_TOKEN_REQUEST_URL");
    string requestToken = os:getEnv("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
    if requestUrl == "" || requestToken == "" {
        return error("ACTIONS_ID_TOKEN_REQUEST_URL is not set; the job needs `permissions: id-token: write`");
    }
    http:Client oidc = check new (string `${requestUrl}&audience=${GHA_AUDIENCE}`);
    record {string value;} response = check oidc->get("", {"Authorization": string `bearer ${requestToken}`});
    return response.value;
}

isolated function resetGhaProviderCalls() {
    lock {
        ghaProviderCalls = 0;
    }
}

isolated function getGhaProviderCalls() returns int {
    lock {
        return ghaProviderCalls;
    }
}

function ghaWifConfig(IdentityTokenSource identityToken) returns WorkloadIdentityConfig {
    WorkloadIdentityConfig config = {
        federationRuleId: ghaFederationRuleId,
        organizationId: ghaOrganizationId,
        serviceAccountId: ghaServiceAccountId,
        identityToken
    };
    if ghaWorkspaceId != "" {
        config.workspaceId = ghaWorkspaceId;
    }
    return config;
}

function checkGhaConfigured() returns error? {
    if ghaOrganizationId == "" || ghaFederationRuleId == "" || ghaServiceAccountId == "" {
        return error("ghaOrganizationId, ghaFederationRuleId and ghaServiceAccountId must be set in tests/Config.toml");
    }
}

function ghaLiveCall(ModelProvider provider, string label) returns error? {
    ai:ChatAssistantMessage reply = check provider->chat([{role: ai:USER, content: "Reply with the single word: pong"}]);
    io:println(string `[gha] ${label} chat -> ${reply.content ?: "<no content>"}`);
    int answer = check provider->generate(`What is 2 + 3? Answer with the number only.`);
    io:println(string `[gha] ${label} generate -> ${answer}`);
    test:assertEquals(answer, 5);
}

// Shows the real GitHub token's claims, which the federation rule matches against.
@test:Config {groups: ["gha"]}
function testGhaIdentityTokenClaims() returns error? {
    [jwt:Header, jwt:Payload] [_, payload] = check jwt:decode(check githubActionsIdentityToken());
    int lifetime = (payload.exp ?: 0) - (payload.iat ?: 0);
    io:println(string `[gha] iss=${payload.iss ?: ""} sub=${payload.sub ?: ""} aud=${payload.aud.toString()} ` +
        string `lifetime=${lifetime}s jti=${payload.jti is string ? "present" : "absent"}`);
    test:assertEquals(payload.iss, GHA_ISSUER);
    test:assertEquals(payload.aud, GHA_AUDIENCE);
}

// Identity token from a function: chat and generate with an access token exchanged from a real GitHub JWT.
@test:Config {groups: ["gha"], dependsOn: [testGhaIdentityTokenClaims]}
function testGhaWifWithTokenProvider() returns error? {
    check checkGhaConfigured();
    check ghaLiveCall(check new (ghaWifConfig(githubActionsIdentityToken), LIVE_GHA_MODEL), "WIF provider");
}

// The access token is cached: several requests need only one exchange, so the provider is called once.
@test:Config {groups: ["gha"], dependsOn: [testGhaIdentityTokenClaims]}
function testGhaWifCachesAccessToken() returns error? {
    check checkGhaConfigured();
    resetGhaProviderCalls();
    AuthProvider provider = check createAuthProvider(ghaWifConfig(githubActionsIdentityToken), {});
    _ = check provider.getHeaders();
    _ = check provider.getHeaders();
    _ = check provider.getHeaders();
    test:assertEquals(getGhaProviderCalls(), 1);
    io:println("[gha] 3 requests -> 1 exchange");
}

// Each exchange fetches a new JWT with its own jti, so separate exchanges all succeed.
@test:Config {groups: ["gha"], dependsOn: [testGhaIdentityTokenClaims]}
function testGhaWifFreshTokenPerExchange() returns error? {
    check checkGhaConfigured();
    resetGhaProviderCalls();
    foreach int i in 1 ... 3 {
        AuthProvider provider = check createAuthProvider(ghaWifConfig(githubActionsIdentityToken), {});
        _ = check provider.getHeaders();
    }
    test:assertEquals(getGhaProviderCalls(), 3);
    io:println("[gha] 3 exchanges with 3 fresh GitHub JWTs -> all accepted");
}

// Identity token from a file that another process keeps rewriting, as a platform would.
@test:Config {groups: ["gha"], dependsOn: [testGhaIdentityTokenClaims]}
function testGhaWifWithTokenFile() returns error? {
    check checkGhaConfigured();
    string path = os:getEnv("GHA_IDENTITY_TOKEN_FILE");
    if path == "" {
        return error("GHA_IDENTITY_TOKEN_FILE is not set");
    }
    check ghaLiveCall(check new (ghaWifConfig({path}), LIVE_GHA_MODEL), "WIF file");
}

const LIVE_GHA_MODEL = CLAUDE_HAIKU_4_5;
