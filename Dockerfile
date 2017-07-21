# bnfinet/lasso
# https://github.com/bnfinet/lasso
FROM golang:1.8

RUN mkdir -p ${GOPATH}/src/github.com/bnfinet/lasso
WORKDIR ${GOPATH}/src/github.com/bnfinet/lasso
COPY . .

RUN go-wrapper download   # "go get -d -v ./..."
RUN go-wrapper install    # "go install -v ./..."

EXPOSE 9090
CMD ["./main"] 
