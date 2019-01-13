# lassoproject/lasso
# https://github.com/LassoProject/lasso
FROM golang:1.10 AS builder

LABEL maintainer="lasso@bnf.net"

RUN mkdir -p ${GOPATH}/src/github.com/LassoProject/lasso
WORKDIR ${GOPATH}/src/github.com/LassoProject/lasso

COPY . .

# RUN go-wrapper download  # "go get -d -v ./..."
# RUN ./do.sh build    # see `do.sh` for lasso build details
# RUN go-wrapper install # "go install -v ./..."

RUN ./do.sh goget
RUN ./do.sh gobuildstatic # see `do.sh` for lasso build details
RUN ./do.sh install

FROM scratch
LABEL maintainer="lasso@bnf.net"
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY templates/ templates/
COPY --from=builder /go/bin/lasso /lasso
EXPOSE 9090
ENTRYPOINT ["/lasso"]
