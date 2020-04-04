package main

// vouch
// github.com/vouch/vouch-proxy

import (
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/vouch/vouch-proxy/pkg/response"

	"github.com/vouch/vouch-proxy/pkg/cookie"
	"github.com/vouch/vouch-proxy/pkg/jwtmanager"

	"github.com/vouch/vouch-proxy/pkg/domains"

	"github.com/gorilla/mux"
	"go.uber.org/zap"

	"github.com/vouch/vouch-proxy/handlers"
	"github.com/vouch/vouch-proxy/pkg/cfg"
	"github.com/vouch/vouch-proxy/pkg/timelog"
)

// version and semver get overwritten by build with
// go build -i -v -ldflags="-X main.version=$(git describe --always --long) -X main.semver=v$(git semver get)"
var (
	version   = "undefined"
	builddt   = "undefined"
	host      = "undefined"
	semver    = "undefined"
	branch    = "undefined"
	staticDir = "/static/"
	logger    *zap.SugaredLogger
	fastlog   *zap.Logger
)

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
	cfg.Configure()
	logger = cfg.Cfg.Logger
	fastlog = cfg.Cfg.FastLogger
	domains.Configure()
	jwtmanager.Configure()
	cookie.Configure()
	handlers.Configure()
	timelog.Configure()
	response.Configure()
}

func main() {
	configure()
	var listen = cfg.Cfg.Listen + ":" + strconv.Itoa(cfg.Cfg.Port)
	checkTCPPortAvailable(listen)
	logger.Infow("starting "+cfg.Branding.CcName,
		// "semver":    semver,
		"version", version,
		"buildtime", builddt,
		"buildhost", host,
		"branch", branch,
		"semver", semver,
		"listen", listen,
		"oauth.provider", cfg.GenOAuth.Provider)

	muxR := mux.NewRouter()

	authH := http.HandlerFunc(handlers.ValidateRequestHandler)
	muxR.HandleFunc("/validate", timelog.TimeLog(authH))
	muxR.HandleFunc("/_external-auth-{id}", timelog.TimeLog(authH))

	loginH := http.HandlerFunc(handlers.LoginHandler)
	muxR.HandleFunc("/login", timelog.TimeLog(loginH))

	logoutH := http.HandlerFunc(handlers.LogoutHandler)
	muxR.HandleFunc("/logout", timelog.TimeLog(logoutH))

	callH := http.HandlerFunc(handlers.CallbackHandler)
	muxR.HandleFunc("/auth", timelog.TimeLog(callH))

	healthH := http.HandlerFunc(handlers.HealthcheckHandler)
	muxR.HandleFunc("/healthcheck", timelog.TimeLog(healthH))

	// setup static
	sPath, err := filepath.Abs(cfg.RootDir + staticDir)
	if fastlog.Core().Enabled(zap.DebugLevel) {
		if err != nil {
			logger.Errorf("couldn't find static assets at %s", sPath)
		}
		logger.Debugf("serving static files from %s", sPath)
	}
	// https://golangcode.com/serve-static-assets-using-the-mux-router/
	muxR.PathPrefix(staticDir).Handler(http.StripPrefix(staticDir, http.FileServer(http.Dir(sPath))))

	srv := &http.Server{
		Handler: muxR,
		Addr:    listen,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		ErrorLog:     log.New(&fwdToZapWriter{fastlog}, "", 0),
	}

	logger.Fatal(srv.ListenAndServe())

}

func checkTCPPortAvailable(listen string) {
	logger.Debug("checking availability of tcp port: " + listen)
	conn, err := net.Listen("tcp", listen)
	if err != nil {
		logger.Error(err)
		logger.Fatal(errors.New(listen + " is not available (is " + cfg.Branding.CcName + " already running?)"))
	}
	if err = conn.Close(); err != nil {
		logger.Error(err)
	}
}
