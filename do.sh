#!/bin/bash

# change dir to where this script is running
CURDIR=${PWD}
SCRIPT=$(readlink -f "$0")
SDIR=$(dirname "$SCRIPT")
cd $SDIR

export LASSO_ROOT=${GOPATH}/src/github.com/LassoProject/lasso/

IMAGE=lassoproject/lasso
GOIMAGE=golang:1.10
NAME=lasso
HTTPPORT=9090
GODOC_PORT=5050

run () {
  go run main.go
}

build () {
  local VERSION=$(git describe --always --long)
  local DT=$(date --rfc-3339=seconds --universal| sed 's/ /T/')
  local FQDN=$(hostname --fqdn)
  local SEMVER=$(git tag --list --sort="v:refname" | tail -n -1)
  local BRANCH=$(git rev-parse --abbrev-ref HEAD)
  go build -i -v -ldflags=" -X main.version=${VERSION} -X main.builddt=${DT} -X main.host=${FQDN} -X main.semver=${SEMVER} -X main.branch=${BRANCH}" .
}

install () {
  cp ./lasso ${GOPATH}/bin/lasso
}

gogo () {
  docker run --rm -i -t -v /var/run/docker.sock:/var/run/docker.sock -v ${SDIR}/go:/go --name gogo $GOIMAGE $*
}

dbuild () {
  docker build -f Dockerfile -t $IMAGE .
}

gobuildstatic () {
  # TODO: this doesn't include the templates
  # https://github.com/shurcooL/vfsgen

  CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .
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
    $CMD &
    WATCH_PID=$!
    echo WATCH_PID $WATCH_PID
    # FIRST_TIME=1
    while inotifywait -q --exclude *.db --exclude './.git/FETCH_HEAD' --exclude do.sh -e modify -r .; do
      if [ -n "$WATCH_PID" ]; then
        echo "killing $WATCH_PID and restarting $CMD"
        kill $WATCH_PID
        sleep 3
      fi
     echo -e "\n---restart---\n"
	   $CMD &
     WATCH_PID=$!
     echo WATCH_PID $WATCH_PID
   done;
}

goget () {
  # install all the things
  go get -v ./...
}

test () {
  # test all the things
  if [ -n "$*" ]; then
    go test -v $*
  else
    go test -v ./...
  fi
}

DB=data/lasso_bolt.db
browsebolt() {
	${GOPATH}/bin/boltbrowser $DB
}

usage() {
   cat <<EOF
   usage:
     $0 run                    - go run main.go
     $0 build                  - go build
     $0 install                - move binary to ${GOPATH}/bin/lasso
     $0 goget                  - get all dependencies
     $0 dbuild                 - build docker container
     $0 drun [args]            - run docker container
     $0 test [./pkg_test.go]   - run go tests (defaults to all tests)
     $0 browsebolt             - browse the boltdb at ${DB}
     $0 gogo [gocmd]           - run, build, any go cmd
     $0 watch [cmd]]           - watch the $CWD for any change and re-reun the [cmd]

  do is like make

EOF

}

ARG=$1; shift;

case "$ARG" in
   'run'|'build'|'browsebolt'|'dbuild'|'drun'|'install'|'test'|'goget'|'gogo'|'watch'|'gobuildstatic')
   $ARG $*
   ;;
   'godoc')
   echo "godoc running at http://${GODOC_PORT}"
   godoc -http=:${GODOC_PORT}
   ;;
   'all')
   gobuildstatic
   dbuild
   drun $*
   ;;
   *)
   usage
   ;;
esac

exit;
