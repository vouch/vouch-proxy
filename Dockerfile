# lassoproject/lasso
# https://github.com/LassoProject/lasso
FROM golang:1.10

LABEL maintainer="lasso@bnf.net"

RUN mkdir -p ${GOPATH}/src/github.com/LassoProject/lasso
WORKDIR ${GOPATH}/src/github.com/LassoProject/lasso
    
COPY . .

# RUN go-wrapper download  # "go get -d -v ./..."
# RUN ./do.sh build    # see `do.sh` for lasso build details
# RUN go-wrapper install # "go install -v ./..."

RUN go get -d -v ./...
RUN ./do.sh build    # see `do.sh` for lasso build details
RUN ./do.sh install

RUN rm -rf ./config ./data \
    && ln -s /config ./config \
    && ln -s /data ./data 

EXPOSE 9090
CMD ["/go/bin/lasso"] 
