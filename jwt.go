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
	"context"
	"net/http"
	"time"

	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"log"

	"reflect"

	"io"

	"bytes"

	"github.com/dgrijalva/jwt-go"
)

type JwtConfig struct {
	PubRsa    string
	ForceAuth bool
	ForceUser bool
}

type Jwt struct {
	UserId         string                 `json:"sub"`
	ResourceAccess map[string]Resource    `json:"resource_access"`
	RealmAccess    Resource               `json:"realm_access"`
	Map            map[string]interface{} `json:"-"`
	Impersonate    JwtImpersonate         `json:"-"`
}

type JwtImpersonate string

type Resource struct {
	Roles []string `json:"roles"`
}

func (router *Router) jwt(r *http.Request) (token Jwt, err error) {
	token.Map = map[string]interface{}{}
	auth := r.Header.Get("Authorization")
	if auth == "" {
		if router.JwtConf.ForceAuth {
			err = errors.New("missing Authorization header")
		}
	} else {
		if router.JwtConf.PubRsa == "" {
			err = GetJWTPayload(auth, &token.Map, &token)
			if err != nil {
				log.Println("error in GetJWTPayload() ", err)
			}
		} else {
			err = GetJWTPayloadAndValidate(auth, router.JwtConf.PubRsa, &token.Map, &token)
			if err != nil {
				log.Println("error in GetJWTPayloadAndValidate() ", err)
			}
		}
	}
	if err == nil && router.JwtConf.ForceUser && token.UserId == "" {
		err = errors.New("missing user id")
	}
	token.Impersonate = JwtImpersonate(auth)
	return
}

func GetJWTPayload(auth string, results ...interface{}) (err error) {
	authParts := strings.Split(auth, " ")
	if len(authParts) != 2 {
		return errors.New("expect auth string format like '<type> <token>'")
	}
	tokenString := authParts[1]
	tokenParts := strings.Split(tokenString, ".")
	if len(tokenParts) != 3 {
		return errors.New("expect token string format like '<head>.<payload>.<sig>'")
	}
	payloadSegment := tokenParts[1]
	err = DecodeJWTSegment(payloadSegment, results...)
	return
}

// Decode JWT specific base64url encoding with padding stripped
func DecodeJWTSegment(seg string, results ...interface{}) error {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	b, err := base64.URLEncoding.DecodeString(seg)
	if err != nil {
		log.Println("error while base64.URLEncoding.DecodeString()", err, seg)
		return err
	}

	for _, result := range results {
		err = json.Unmarshal(b, result)
		if err != nil {
			log.Println("error while json.Unmarshal()", err, reflect.TypeOf(result).Kind().String(), string(b))
			return err
		}
	}

	return nil
}

func GetJWTPayloadAndValidate(auth string, pubRsaKey string, results ...interface{}) (err error) {
	authParts := strings.Split(auth, " ")
	if len(authParts) != 2 {
		return errors.New("expect auth string format like '<type> <token>'")
	}
	tokenString := authParts[1]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		//decode key base64 string to []byte
		b, err := base64.StdEncoding.DecodeString(pubRsaKey)
		if err != nil {
			return nil, err
		}
		//parse []byte key to go struct key (use most common encoding)
		return x509.ParsePKIXPublicKey(b)
	})

	if err != nil {
		return err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		b, err := json.Marshal(claims)
		if err != nil {
			return err
		}
		for _, result := range results {
			err = json.Unmarshal(b, result)
			if err != nil {
				return err
			}
		}
	} else {
		err = errors.New("no valida JWT payload found")
	}
	return
}

func (this JwtImpersonate) Post(url string, contentType string, body io.Reader) (resp *http.Response, err error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	ctx, _ := context.WithTimeout(context.Background(), 5 * time.Second)
	req.WithContext(ctx)
	req.Header.Set("Authorization", string(this))
	req.Header.Set("Content-Type", contentType)

	resp, err = http.DefaultClient.Do(req)

	if err == nil && resp.StatusCode >= 300 {
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		resp.Body.Close()
		log.Println(buf.String())
		err = errors.New(resp.Status)
	}
	return
}

func (this JwtImpersonate) PostJSON(url string, body interface{}, result interface{}) (err error) {
	b := new(bytes.Buffer)
	err = json.NewEncoder(b).Encode(body)
	if err != nil {
		return
	}
	resp, err := this.Post(url, "application/json", b)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if result != nil {
		err = json.NewDecoder(resp.Body).Decode(result)
	}
	return
}

func (this JwtImpersonate) Get(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	ctx, _ := context.WithTimeout(context.Background(), 5 * time.Second)
	req.WithContext(ctx)
	req.Header.Set("Authorization", string(this))
	resp, err = http.DefaultClient.Do(req)

	if err == nil && resp.StatusCode >= 300 {
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		resp.Body.Close()
		log.Println(buf.String())
		err = errors.New(resp.Status)
	}
	return
}

func (this JwtImpersonate) GetJSON(url string, result interface{}) (err error) {
	resp, err := this.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(result)
}
