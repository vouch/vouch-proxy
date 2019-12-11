#!/bin/bash
set -e

# change dir to where this script is running
CURDIR=${PWD}
# mac support (brew install coreutils)
if [[ "$OSTYPE" == "darwin"* ]]; then
  SCRIPT=$(greadlink -f "$0")
# assume standard unix/linux
else
  SCRIPT=$(readlink -f "$0")
fi
SDIR=$(dirname "$SCRIPT")
cd $SDIR

export VOUCH_ROOT=${GOPATH}/src/github.com/vouch/vouch-proxy/

IMAGE=voucher/vouch-proxy
GOIMAGE=golang:1.10
NAME=vouch-proxy
HTTPPORT=9090
GODOC_PORT=5050

run () {
  go run main.go
}

build () {
  local VERSION=$(git describe --always --long)
  local DT=$(date -u +"%Y-%m-%dT%H:%M:%SZ") # ISO-8601
  local FQDN=$(hostname --fqdn)
  local SEMVER=$(git tag --list --sort="v:refname" | tail -n -1)
  local BRANCH=$(git rev-parse --abbrev-ref HEAD)
  go build -i -v -ldflags=" -X main.version=${VERSION} -X main.builddt=${DT} -X main.host=${FQDN} -X main.semver=${SEMVER} -X main.branch=${BRANCH}" .
}

install () {
  cp ./vouch-proxy ${GOPATH}/bin/vouch-proxy
}

gogo () {
  docker run --rm -i -t -v /var/run/docker.sock:/var/run/docker.sock -v ${SDIR}/go:/go --name gogo $GOIMAGE $*
}

dbuild () {
  docker build -f Dockerfile -t $IMAGE .
}

gobuildstatic () {
  export CGO_ENABLED=0
  export GOOS=linux
  build
}

drun () {
   if [ "$(docker ps | grep $NAME)" ]; then
      docker stop $NAME
      docker rm $NAME
   fi

   CMD="docker run --rm -i -t
    -p ${HTTPPORT}:${HTTPPORT}
    --name $NAME
    -v ${SDIR}/config:/config
    -v ${SDIR}/data:/data
    $IMAGE $* "

    echo $CMD
    $CMD
}


watch () {
  CMD=$@;
  if [ -z "$CMD" ]; then
      CMD="go run main.go"
  fi
  clear
  echo -e "starting watcher for:\n\t$CMD"

  # TODO: add *.tmpl and *.css
  # find . -type f -name '*.css' | entr -cr $CMD
  find . -name '*.go' | entr -cr $CMD
}

goget () {
  # install all the things
  go get -t -v ./...
}

REDACT=""
bug_report() {
  set +e
  # CONFIG=$1; shift;
  CONFIG=config/config.yml
  REDACT=$*

  if [ -z "$REDACT" ]; then
    cat <<EOF

    bug_report cleans the ${CONFIG} and the Vouch Proxy logs of secrets and any additional strings (usually domains and email addresses)

    usage:

      $0 bug_report redacted_string redacted_string

EOF
    exit 1;
  fi
  echo -e "\n-------------------------\n\n#\n# redacted Vouch Proxy ${CONFIG}\n# $(date -I)\n#\n"
  cat $CONFIG | _redact

  echo -e "\n-------------------------\n\n#\n# redacted Vouch Proxy logs\n# $(date -I)\n#\n"
  echo -e "# be sure to set 'vouch.testing: true' and 'vouch.logLevel: debug' in your config\n"

  trap _redact_exit SIGINT
  ./vouch-proxy 2>&1 | _redact


}
_redact_exit () {
  echo -e "\n\n-------------------------\n"
  echo -e "redact your nginx config with:\n"
  echo -e "\tcat nginx.conf | sed 's/yourdomain.com/DOMAIN.COM/g'\n"
  echo -e "Please upload both configs and some logs to https://hastebin.com/ and open an issue on GitHub at https://github.com/vouch/vouch-proxy/issues\n"
}

_redact() {
  SECRET_FIELDS=("client_id client_secret secret")
  while IFS= read -r LINE; do
    for i in $SECRET_FIELDS; do
      LINE=$(echo "$LINE" | sed -r "s/${i}..[[:graph:]]*\>/${i}: XXXXXXXXXXX/g")
    done
    # j=$(expr $j + 1)
    for i in $REDACT; do
      r=$i
      r=$(echo "$r" | sed "s/[[:alnum:]]/+/g")
      # LINE=$(echo "$LINE" | sed "s/${i}/+++++++/g")
      LINE=$(echo "$LINE" | sed "s/${i}/${r}/g")
    done
    echo "${LINE}"
  done
}

coverage() {
  export EXTRA_TEST_ARGS='-cover'
  test
  go tool cover -html=coverage.out -o coverage.html
}

test () {
  if [ -z "$VOUCH_CONFIG" ]; then
    export VOUCH_CONFIG="$SDIR/config/test_config.yml"
  fi
  # test all the things
  if [ -n "$*" ]; then
    go test -v -race $EXTRA_TEST_ARGS $*
  else
    go test -v -race $EXTRA_TEST_ARGS ./...
  fi
}

stats () {
  echo -n "lines of code: "
  find . -name '*.go' | xargs wc -l | grep total | cut -d' ' -f2

  echo -n "number of go files: "
  find . -name '*.go' | wc -l
}

DB=data/vouch_bolt.db
browsebolt() {
	${GOPATH}/bin/boltbrowser $DB
}

usage() {
   cat <<EOF
   usage:
     $0 run                    - go run main.go
     $0 build                  - go build
     $0 install                - move binary to ${GOPATH}/bin/vouch
     $0 goget                  - get all dependencies
     $0 dbuild                 - build docker container
     $0 drun [args]            - run docker container
     $0 test [./pkg_test.go]   - run go tests (defaults to all tests)
     $0 coverage               - coverage report
     $0 bug_report domain.com  - print config file removing secrets and each provided domain
     $0 browsebolt             - browse the boltdb at ${DB}
     $0 gogo [gocmd]           - run, build, any go cmd
     $0 stats                  - simple metrics (lines of code in project, number of go files)
     $0 watch [cmd]]           - watch the $CWD for any change and re-reun the [cmd]

  do is like make

EOF
  exit 1

}

ARG=$1;

case "$ARG" in
   'run'|'build'|'browsebolt'|'dbuild'|'drun'|'install'|'test'|'goget'|'gogo'|'watch'|'gobuildstatic'|'coverage'|'stats'|'usage'|'bug_report')
   shift
   $ARG $*
   ;;
   'godoc')
   echo "godoc running at http://${GODOC_PORT}"
   godoc -http=:${GODOC_PORT}
   ;;
   'all')
   shift
   gobuildstatic
   dbuild
   drun $*
   ;;
   *)
   usage
   ;;
esac

exit;
