FROM alpine
RUN mkdir /go
ENV GOPATH /go
ADD . /go/src/github.com/badkode/arpscan
RUN apk add --update go gcc g++ libpcap libpcap-dev git && \
	go get github.com/google/gopacket && \
	go get github.com/jasonlvhit/gocron && \
	go get gopkg.in/yaml.v2 && \
	go install github.com/badkode/arpscan && \
	apk del git go gcc g++ libpcap-dev && \
    rm -rf /go/pkg && \
    rm -rf /go/src && \
    rm -rf /var/cache/apk/*

ADD manuf.txt /go/bin/
ADD arpscan.yaml /go/bin/
WORKDIR /go/bin
ENTRYPOINT ["/go/bin/arpscan"]