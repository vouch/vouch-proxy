# voucher/vouch
# https://github.com/vouch/vouch
FROM golang:1.10

LABEL maintainer="vouch@bnf.net"

RUN mkdir -p ${GOPATH}/src/github.com/vouch/vouch
WORKDIR ${GOPATH}/src/github.com/vouch/vouch
    
COPY . .

# RUN go-wrapper download  # "go get -d -v ./..."
# RUN ./do.sh build    # see `do.sh` for vouch build details
# RUN go-wrapper install # "go install -v ./..."

RUN go get -d -v ./...
RUN ./do.sh build    # see `do.sh` for vouch build details
RUN ./do.sh install

RUN rm -rf ./config ./data \
    && ln -s /config ./config \
    && ln -s /data ./data 

EXPOSE 9090
CMD ["/go/bin/vouch"] 
