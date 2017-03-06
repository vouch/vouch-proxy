#!/bin/bash

# change dir to where this script is running
CURDIR=${PWD}
SCRIPT=$(readlink -f "$0")
SDIR=$(dirname "$SCRIPT")
cd $SDIR

export LASSO_ROOT=/home/bfoote/go/src/git.fs.bnf.net/bnfinet/lasso/

IMAGE=dreg.bnf.net/bnfnet/lasso
GOIMAGE=dreg.bnf.net/bnfnet/golang
NAME=lasso
APIPORT=4040
SWAGGERPORT=4048
SWAGNAME=swagger
GODOC_PORT=5050

usage() {
   cat <<EOF
   usage:
     $0 build            - build docker container
     $0 drun [args]      - run docker container
     $0 gogo [gocmd]     - run, build, any go cmd
     $0 swagger [cmd]    - swagger
     $0 watch [cmd]]     - watch the $CWD for any change and re-reun the [cmd]

EOF


}

gogo () {
    docker run --rm -i -t -v /var/run/docker.sock:/var/run/docker.sock -v ${SDIR}/go:/go --name gogo $GOIMAGE $*
}

dbuild () {
   docker build -f Dockerfile.scratch -t $IMAGE .
}

gobuildstatic () {
  CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .
}

drun () {
   if [ "$(docker ps | grep $NAME)" ]; then
      docker stop $NAME
      docker rm $NAME
   fi

   docker run --rm -i -t --name $NAME $IMAGE $*
}

swagger_gen_server() {
  cd $SDIR/api;
  swagger generate server -A cbp
  go install ./cmd/cbp-server/
}

start_api() {
  $GOPATH/bin/cbp-server --port $APIPORT;
  echo "api:    http://localhost:${APIPORT}"
}

start_api_browser() {

  if [ "$(docker ps -a | grep $SWAGNAME)" ]; then
     docker stop $SWAGNAME
     docker rm $SWAGNAME
  fi
  docker run -d --name $SWAGNAME -p ${SWAGGERPORT}:8080 swaggerapi/swagger-ui
  # swagger serve --no-open --port=${SWAGGERPORT} http://localhost:${APIPORT}/swagger.json &
  echo "swagger: http://localhost:${SWAGGERPORT}/?url=http://localhost:${APIPORT}"
}

swagger () {
#   docker run \
#     --rm \
#     -it \
#     -e GOROOT=${GOROOT} \
#     -e GOPATH=${GOPATH} \
#     -v $HOME:$HOME \
#     -w $CURDIR \
#     quay.io/goswagger/swagger \
#     $@;
  $GOPATH/bin/swagger $@;
}


watch () {
    CMD=$@;
    if [ -z "$CMD" ]; then
	     CMD="go run main.go"
    fi
    clear
    echo -e "starting watcher for:\n\t$CMD"
    $CMD&
    WATCH_PID=$!
    while inotifywait -q --exclude .swp -e modify -r .; do
      if [ -z "$WATCH_PID"]; then
        kill $WATCH_PID
        sleep 3
      fi
      clear
	    $CMD&
      WATCH_PID=$!
    done;
}

goget () {
  # install all the things
  go get -v ./...
}
test () {
  # install all the things
  go test -v $*
}

ARG=$1; shift;

# I think these can be replaced with
#   build|drun|....)
#      $ARG $*
#      ;;
case "$ARG" in
   'build')
#   gobuildstatic
   dbuild
   ;;
   'drun')
   drun $*
   ;;
   'test')
   test $*
   ;;
   'godoc')
   echo "godoc running at http://${GODOC_PORT}"
   godoc -http=:${GODOC_PORT}
   ;;
   'goget'|'get')
   goget $*
   ;;
   'gogo')
   gogo $*
   ;;
   'watch')
   watch $*
   ;;
   'swagger')
   swagger $*
   ;;
   'startapi')
   start_api &
   start_api_browser
   ;;
   'gobuildstatic')
   gobuildstatic $*
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
