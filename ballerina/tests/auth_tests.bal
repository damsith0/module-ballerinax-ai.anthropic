// Copyright (c) 2026 WSO2 LLC. (http://www.wso2.org).
//
// WSO2 Inc. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/test;

const AUTH_SERVICE_URL = "http://localhost:8080/llm/anthropic/auth";
const BEARER_TOKEN = "not-a-real-bearer-token";

isolated function getAuthRequestHeaders(string scenario) returns json {
    lock {
        return authRequestHeaders[scenario].clone();
    }
}

@test:Config
function testChatSendsOnlyApiKeyWhenAuthIsNotConfigured() returns error? {
    ModelProvider provider = check new (API_KEY, CLAUDE_3_7_SONNET_20250219, AUTH_SERVICE_URL + "/apiKeyChat");
    _ = check provider->chat({role: "user", content: "Hi"});
    test:assertEquals(getAuthRequestHeaders("apiKeyChat"), {authorization: (), apiKey: API_KEY});
}

@test:Config
function testChatSendsOnlyBearerTokenWhenApiKeyIsNotProvided() returns error? {
    ModelProvider provider = check new ((), CLAUDE_3_7_SONNET_20250219, AUTH_SERVICE_URL + "/bearerChat",
        auth = {token: BEARER_TOKEN});
    _ = check provider->chat({role: "user", content: "Hi"});
    test:assertEquals(getAuthRequestHeaders("bearerChat"),
        {authorization: string `Bearer ${BEARER_TOKEN}`, apiKey: ()});
}

@test:Config
function testGenerateSendsOnlyBearerTokenWhenApiKeyIsNotProvided() returns error? {
    ModelProvider provider = check new ((), CLAUDE_3_7_SONNET_20250219, AUTH_SERVICE_URL + "/bearerGenerate",
        auth = {token: BEARER_TOKEN});
    int result = check provider->generate(`What is 2 + 2?`);
    test:assertEquals(result, 4);
    test:assertEquals(getAuthRequestHeaders("bearerGenerate"),
        {authorization: string `Bearer ${BEARER_TOKEN}`, apiKey: ()});
}

@test:Config
function testChatSendsBothApiKeyAndBearerTokenWhenBothAreProvided() returns error? {
    ModelProvider provider = check new (API_KEY, CLAUDE_3_7_SONNET_20250219, AUTH_SERVICE_URL + "/apiKeyAndBearerChat",
        auth = {token: BEARER_TOKEN});
    _ = check provider->chat({role: "user", content: "Hi"});
    test:assertEquals(getAuthRequestHeaders("apiKeyAndBearerChat"),
        {authorization: string `Bearer ${BEARER_TOKEN}`, apiKey: API_KEY});
}
