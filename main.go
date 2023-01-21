/*

Copyright 2020 The Vouch Proxy Authors.
Use of this source code is governed by The MIT License (MIT) that
can be found in the LICENSE file. Software distributed under The
MIT License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.

*/

package main

// Vouch Proxy
// github.com/vouch/vouch-proxy

/*

Hello Developer!  Thanks for looking at the code!

Before submitting PRs, please see the README...
https://github.com/vouch/vouch-proxy#submitting-a-pull-request-for-a-new-feature

*/

import (
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	// "net/http/pprof"

	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"

	"github.com/vouch/vouch-proxy/handlers"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/cookie"
	"github.com/vouch/vouch-proxy/pkg/domains"
	"github.com/vouch/vouch-proxy/pkg/healthcheck"
	"github.com/vouch/vouch-proxy/pkg/jwtmanager"
	"github.com/vouch/vouch-proxy/pkg/responses"
	"github.com/vouch/vouch-proxy/pkg/timelog"
)

// `version`, `semver` and others are populated during build by..
// go build -i -v -ldflags="-X main.version=$(git describe --always --long) -X main.semver=v$(git semver get)"
var (
	version     = "undefined"
	builddt     = "undefined"
	host        = "undefined"
	semver      = "undefined"
	branch      = "undefined"
	uname       = "undefined"
	logger      *zap.SugaredLogger
	fastlog     *zap.Logger
	showVersion = flag.Bool("version", false, "display version and exit")
	help        = flag.Bool("help", false, "show usage")
	scheme      = map[bool]string{
		false: "http",
		true:  "https",
	}
	// doProfile = flag.Bool("profile", false, "run profiler at /debug/pprof")
)

//go:embed static
var staticFs embed.FS

//go:embed templates
var templatesFs embed.FS

//go:embed .defaults.yml
var defaultsFs embed.FS

// fwdToZapWriter allows us to use the zap.Logger as our http.Server ErrorLog
// see https://stackoverflow.com/questions/52294334/net-http-set-custom-logger
type fwdToZapWriter struct {
	logger *zap.Logger
}

func (fw *fwdToZapWriter) Write(p []byte) (n int, err error) {
	fw.logger.Error(string(p))
	return len(p), nil
}

// configure() is essentially init()
// for most other projects you would think of this as init()
// this epic issue related to the flag.parse change of behavior for go 1.13 explains some of what's going on here
// https://github.com/golang/go/issues/31859
// essentially, flag.parse() must be called in vouch-proxy's main() and *not* in init()
// this has a cascading effect on the zap logger since the log level can be set on the command line
// configure() explicitly calls package configure functions (domains.Configure() etc) mostly to set the logger
// without this setup testing and logging are screwed up
func configure() {
	flag.Parse()

	if *help {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *showVersion {
		fmt.Printf("%s\n", semver)
		os.Exit(0)
	}

	cfg.Templates = templatesFs
	cfg.Defaults = defaultsFs

	cfg.Configure()
	healthcheck.CheckAndExitIfIsHealthCheck()

	logger = cfg.Logging.Logger
	fastlog = cfg.Logging.FastLogger

	if err := cfg.ValidateConfiguration(); err != nil {
		logger.Fatal(err)
	}

	domains.Configure()
	jwtmanager.Configure()
	cookie.Configure()
	responses.Configure()
	handlers.Configure()
	timelog.Configure()
}

func main() {
	configure()
	listenStr := cfg.Cfg.Listen
	if !strings.HasPrefix(cfg.Cfg.Listen, "unix:") {
		listenStr = cfg.Cfg.Listen + ":" + strconv.Itoa(cfg.Cfg.Port)
		checkTCPPortAvailable(listenStr)
	}

	tls := (cfg.Cfg.TLS.Cert != "" && cfg.Cfg.TLS.Key != "")
	logger.Infow("starting "+cfg.Branding.FullName,
		// "semver":    semver,
		"version", version,
		"buildtime", builddt,
		"uname", uname,
		"buildhost", host,
		"branch", branch,
		"semver", semver,
		"listen", scheme[tls]+"://"+listenStr,
		"tls", tls,
		"document_root", cfg.Cfg.DocumentRoot,
		"oauth.provider", cfg.GenOAuth.Provider)

	// router := mux.NewRouter()
	router := httprouter.New()

	if cfg.Cfg.DocumentRoot != "" {
		logger.Debugf("adjusting all served URIs to be under %s", cfg.Cfg.DocumentRoot)
	}

	authH := http.HandlerFunc(handlers.ValidateRequestHandler)
	router.HandlerFunc(http.MethodGet, cfg.Cfg.DocumentRoot+"/validate", timelog.TimeLog(jwtmanager.JWTCacheHandler(authH)))
	router.HandlerFunc(http.MethodGet, cfg.Cfg.DocumentRoot+"/_external-auth-:id", timelog.TimeLog(jwtmanager.JWTCacheHandler(authH)))

	loginH := http.HandlerFunc(handlers.LoginHandler)
	router.HandlerFunc(http.MethodGet, cfg.Cfg.DocumentRoot+"/login", timelog.TimeLog(loginH))

	logoutH := http.HandlerFunc(handlers.LogoutHandler)
	router.HandlerFunc(http.MethodGet, cfg.Cfg.DocumentRoot+"/logout", timelog.TimeLog(logoutH))

	callH := http.HandlerFunc(handlers.CallbackHandler)
	router.HandlerFunc(http.MethodGet, cfg.Cfg.DocumentRoot+"/auth", timelog.TimeLog(callH))

	authStateH := http.HandlerFunc(handlers.AuthStateHandler)
	router.HandlerFunc(http.MethodGet, cfg.Cfg.DocumentRoot+"/auth/:state/", timelog.TimeLog(authStateH))

	healthH := http.HandlerFunc(handlers.HealthcheckHandler)
	router.HandlerFunc(http.MethodGet, "/healthcheck", timelog.TimeLog(healthH))

	// this is the documented implemenation for static file serving but it doesn't seem to work with go:embed
	// router.ServeFiles("/static/*filepath", http.FS(staticFs))

	// so instead we publish all three routes
	router.Handler(http.MethodGet, cfg.Cfg.DocumentRoot+"/static/css/main.css", http.StripPrefix(cfg.Cfg.DocumentRoot, http.FileServer(http.FS(staticFs))))
	router.Handler(http.MethodGet, cfg.Cfg.DocumentRoot+"/static/img/favicon.ico", http.StripPrefix(cfg.Cfg.DocumentRoot, http.FileServer(http.FS(staticFs))))
	router.Handler(http.MethodGet, cfg.Cfg.DocumentRoot+"/static/img/multicolor_V_500x500.png", http.StripPrefix(cfg.Cfg.DocumentRoot, http.FileServer(http.FS(staticFs))))

	// this also works for static files
	// router.NotFound = http.FileServer(http.FS(staticFs))

	//
	// if *doProfile {
	// 	addProfilingHandlers(router)
	// }

	srv := &http.Server{
		Handler: router,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: time.Duration(cfg.Cfg.WriteTimeout) * time.Second,
		ReadTimeout:  time.Duration(cfg.Cfg.ReadTimeout) * time.Second,
		IdleTimeout:  time.Duration(cfg.Cfg.IdleTimeout) * time.Second,
		ErrorLog:     log.New(&fwdToZapWriter{fastlog}, "", 0),
	}

	lis, cleanupFn, err := listen()
	if err != nil {
		logger.Fatal(err)
	}
	defer cleanupFn()

	if tls {
		srv.TLSConfig = cfg.TLSConfig(cfg.Cfg.TLS.Profile)
		logger.Fatal(srv.ServeTLS(lis, cfg.Cfg.TLS.Cert, cfg.Cfg.TLS.Key))
	} else {
		logger.Fatal(srv.Serve(lis))
	}

}

func listen() (lis net.Listener, cleanupFn func(), err error) {
	if !strings.HasPrefix(cfg.Cfg.Listen, "unix:") {
		lis, err = net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.Cfg.Listen, cfg.Cfg.Port))
		return lis, func() {}, err
	}

	socketPath := strings.TrimPrefix(cfg.Cfg.Listen, "unix:")
	_, err = os.Stat(socketPath)
	if err == nil {
		if err = os.Remove(socketPath); err != nil {
			return nil, nil, fmt.Errorf("remove existing socket file %s: %w", socketPath, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("stat socket file %s: %w", socketPath, err)
	}

	lis, err = net.Listen("unix", socketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("listen %s: %w", socketPath, err)
	}

	mode := fs.FileMode(cfg.Cfg.SocketMode) // defaults to 0660 - see .defaults.yml
	if err = os.Chmod(socketPath, mode); err != nil {
		return nil, nil, fmt.Errorf("chmod socket file %s %#o", socketPath, mode)
	}

	if cfg.Cfg.SocketGroup != "" {
		group, err := user.LookupGroup(cfg.Cfg.SocketGroup)
		if err != nil {
			return nil, nil, fmt.Errorf("lookup socket group: %s %w", cfg.Cfg.SocketGroup, err)
		}
		gid, err := strconv.Atoi(group.Gid)
		if err != nil {
			return nil, nil, fmt.Errorf("lookup socket group: invalid gid: %w", err)
		}
		if err := os.Chown(socketPath, -1, gid); err != nil {
			return nil, nil, fmt.Errorf("chown socket: group: %s %w", socketPath, err)
		}
	}
	return lis, func() { _ = os.Remove(socketPath) }, nil
}

func checkTCPPortAvailable(listen string) {
	logger.Debug("checking availability of tcp port: " + listen)
	conn, err := net.Listen("tcp", listen)
	if err != nil {
		logger.Error(err)
		logger.Fatal(errors.New(listen + " is not available (is " + cfg.Branding.FullName + " already running?)"))
	}
	if err = conn.Close(); err != nil {
		logger.Error(err)
	}
}

// if you'd like to enable profiling uncomment these
// func addProfilingHandlers(router *httprouter.Router) {
// 	// https://stackoverflow.com/questions/47452471/pprof-profile-with-julienschmidtrouter-and-benchmarks-not-profiling-handler
// 	logger.Debugf("profiling routes added at http://%s:%d/debug/pprof/", cfg.Cfg.Listen, cfg.Cfg.Port)
// 	router.HandlerFunc(http.MethodGet, "/debug/pprof/", pprof.Index)
// 	router.HandlerFunc(http.MethodGet, "/debug/pprof/cmdline", pprof.Cmdline)
// 	router.HandlerFunc(http.MethodGet, "/debug/pprof/profile", pprof.Profile)
// 	router.HandlerFunc(http.MethodGet, "/debug/pprof/symbol", pprof.Symbol)
// 	router.HandlerFunc(http.MethodGet, "/debug/pprof/trace", pprof.Trace)
// 	router.Handler(http.MethodGet, "/debug/pprof/goroutine", pprof.Handler("goroutine"))
// 	router.Handler(http.MethodGet, "/debug/pprof/heap", pprof.Handler("heap"))
// 	router.Handler(http.MethodGet, "/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
// 	router.Handler(http.MethodGet, "/debug/pprof/block", pprof.Handler("block"))
// }
