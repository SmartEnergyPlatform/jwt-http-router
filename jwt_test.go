/*
 * Copyright 2018 InfAI (CC SES)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jwt_http_router

import (
	"fmt"
	"testing"
)

const auth = `Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJoZDREMmR2dzVTYjNncmlZanR4eTdZaFQtTU1abm9WdDB3R2dqQnpad2U0In0.eyJqdGkiOiJiNGUxMWU0Mi0zNjQ3LTQ2ZWUtYTE2My0xOGVkZWRlOThjM2IiLCJleHAiOjE1MTg0NDUxMDEsIm5iZiI6MCwiaWF0IjoxNTE4NDQxNTAxLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwMDEvYXV0aC9yZWFsbXMvbWFzdGVyIiwiYXVkIjoiZnJvbnRlbmQiLCJzdWIiOiI2NTliNDZmNi1iZTFjLTRiNmYtODdjMy00ZTUxMWFhZTQ4MWMiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJmcm9udGVuZCIsIm5vbmNlIjoiZjVkYmFlMzktYjhkMC00ZjUxLTg2ZTMtNGViZmUzMDA4NWI3IiwiYXV0aF90aW1lIjoxNTE4NDQxNDk5LCJzZXNzaW9uX3N0YXRlIjoiYWFhN2Q0ZTAtNDJjNi00Y2FkLTkwMjUtYWY5NjcwMTFmM2QyIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vbG9jYWxob3N0OjUwMDAiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImNyZWF0ZS1yZWFsbSIsImFkbWluIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJtYXN0ZXItcmVhbG0iOnsicm9sZXMiOlsidmlldy1pZGVudGl0eS1wcm92aWRlcnMiLCJ2aWV3LXJlYWxtIiwibWFuYWdlLWlkZW50aXR5LXByb3ZpZGVycyIsImltcGVyc29uYXRpb24iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInByZWZlcnJlZF91c2VybmFtZSI6InNlcGwifQ.cVHbNDhAmg9_r00TTsXMWjh8KvsyGlqezCl_9M6i3iJghWu0dB6xcUhCNE7IUSXIsFl7aifRooTNgUJI8yUZWVVJkvVySBhOXf1y7p1-yxOCVBmfyhqFYiqbJRh6-DKXNbHZIxsJGSbcf3Z98rG92MTiE51Y6pVvWZW9TIkjSIMU-rnvAQ5UUssPd6T2q1wz0VUNGdbLS1-7JnKjqU7XzEo3xbJdHt_v9NmdKqknvpCxVbYIgCphypM06PZTAKWBUGu_dNRIQ5XoAAIjRy09XTfD9vKQudIk-xpIc6GVdGl1JILeRoLPriVrKPAO_-dotNI2hk_NBUei5rMbZ8dC1A`

func TestJwt(t *testing.T) {
	token := Jwt{}
	token.Map = map[string]interface{}{}
	err := GetJWTPayload(auth, &token.Map, &token)
	fmt.Println(err, token)
	if err != nil {
		t.Error(err)
	}
}

func TestRsaJwt(t *testing.T) {
	t.SkipNow()
	token := Jwt{}
	token.Map = map[string]interface{}{}
	rsa := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApIH2UK4yoHkQQyTVWKvcbtNrfa9t7UBFdgLTYCZ47qjVXLGa6XJG+LDEeMjOZqA7irSfuBayV9CX6rJApxibvfF5UnCbV7hCcpu5cJd2ezWWkcvj08ZpLCbYwI6OQzXIAYwZYSwQQW1VnAfqNryO2Mb8g2f++1C+2PuX0DcpKt8Wz1sjjdoNkbDPHL3JtGUhnLHSCh/Qz0crqIQBwymCj/qKaRaQ8U9VX3xasjGalnOA7z2503KaWlpZV5N6h9QH/FqQ3rVyw/4cnOmwYH705Lqyb0RVan90/vJKbVh8YBbW7JGbRrtbW6jfg9YJSsPBPT8eUV90O9aYQNxB+W/30wIDAQAB"
	err := GetJWTPayloadAndValidate(auth, rsa, &token.Map, &token)
	fmt.Println(err, token)
	if err != nil {
		t.Error(err)
	}
}
