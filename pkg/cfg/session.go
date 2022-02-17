/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package cfg

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/sessions"
	"github.com/rbcervilla/redisstore/v8"
)

func NewSessionStore(sameSite http.SameSite) sessions.Store {
	var store sessions.Store
	var err error

	if Cfg.Redis.Host != "" {
		store, err = newRedisSessionStore(sameSite)
	} else {
		store, err = newCookieSessionStore(sameSite)
	}

	if err != nil {
		log.Fatal("failed to create session store: ", err)
	}

	return store
}

func newSessionOptions(sameSite http.SameSite) *sessions.Options {
	return &sessions.Options{
		HttpOnly: Cfg.Cookie.HTTPOnly,
		Secure:   Cfg.Cookie.Secure,
		SameSite: sameSite,
		MaxAge:   Cfg.Session.MaxAge * 60, // convert minutes to seconds
		Path:     "/",
	}
}

// default storage backend
func newCookieSessionStore(sameSite http.SameSite) (sessions.Store, error) {
	store := sessions.NewCookieStore([]byte(Cfg.Session.Key))

	store.Options = newSessionOptions(sameSite)

	return store, nil
}

func newRedisConnection() (*redis.Options, error) {
	var address string
	var network string
	host := Cfg.Redis.Host
	port := 6379

	if Cfg.Redis.Socket != "" {
		network = "unix"
		address = Cfg.Redis.Socket
	} else {
		if Cfg.Redis.Port > 0 {
			port = Cfg.Redis.Port
		}

		network = "tcp"
		address = fmt.Sprintf("%s:%d", host, port)
	}

	return &redis.Options{
		Network:  network,
		Addr:     address,
		Username: Cfg.Redis.Username,
		Password: Cfg.Redis.Password,
		DB:       Cfg.Redis.DB,
	}, nil
}

// remote K/V based session storage
func newRedisSessionStore(sameSite http.SameSite) (sessions.Store, error) {
	var store *redisstore.RedisStore
	var conn *redis.Options
	var err error

	conn, err = newRedisConnection()
	if err != nil {
		return nil, err
	}

	client := redis.NewClient(conn)
	ctx := context.Background()

	store, err = redisstore.NewRedisStore(ctx, client)
	if err != nil {
		return nil, err
	}

	store.KeyPrefix(Cfg.Redis.KeyPrefix)
	store.Options(*newSessionOptions(sameSite))

	return store, nil
}
