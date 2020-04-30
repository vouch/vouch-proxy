package jwtmanager

import (
	"time"

	cache "github.com/patrickmn/go-cache"
	"github.com/vouch/vouch-proxy/pkg/cfg"
)

// Cache in memory temporary store for responses from /validate for jwt
var Cache *cache.Cache

func cacheConfigure() {

	var expire int = 20 // default 20 minutes

	if cfg.Cfg.JWT.MaxAge < expire {
		expire = cfg.Cfg.JWT.MaxAge
	}
	dExp := time.Duration(expire) * time.Minute
	purgeCheck := dExp / 3
	// log.Debugf("cacheConfigure expire %d dExp %d purgecheck %d", expire, dExp, purgeCheck)
	log.Infof("cacheConfigure expire %d dExp %d purgecheck %d", expire, dExp, purgeCheck)
	Cache = cache.New(dExp, purgeCheck)
}

// Cache an empty struct with methods to access the cache
// var Cache = &cache{}
//
// the same JWT should have the same cached response
// type jwtCacheMap map[string]jcmCacheEntry
//
// type jcmCacheEntry struct {
// expires  int64
// response []byte
// }
//
//
// type cache struct{}
//
// var cacheLock = &sync.RWMutex{}
// var jcm = make(jwtCacheMap)
//
// var errNotFound = errors.New("jwtCache: jwt not found in cache")
// var errExpired = errors.New("jwtCache: jwt is expired, deleted from cache")
//
// func (cache) Get(jwtkey string) ([]byte, error) {
// var entry jcmCacheEntry
// var ok bool
// cacheLock.RLock()
// entry, ok = jcm[jwtkey]
// cacheLock.RUnlock()
// if !ok {
// return nil, errNotFound
// }
// if entry.expires < time.Now().Unix() {
// go Cache.Delete(jwtkey)
// return nil, errExpired
// }
// return entry.response, nil
// }
//
// func (cache) Put(jwtkey string, res []byte, exp int64) error {
// e := jcmCacheEntry{exp, res}
// cacheLock.Lock()
// jcm[jwtkey] = e
// cacheLock.Unlock()
// go func() {
// dur := time.Duration(exp - time.Now().Unix())
// log.Info("jwtcach: sleeping for duration")
// time.Sleep(dur)
// Cache.Delete(jwtkey)
// }()
// return nil
// }
//
// func (cache) Delete(jwtkey string) error {
// cacheLock.Lock()
// delete(jcm, jwtkey)
// cacheLock.Unlock()
// return nil
// }
//
