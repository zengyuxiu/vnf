#!/bin/bash
set -x
rsync -avz ./ fnii@172.171.50.61:~/workspace/go-broker/vnf/flowProbe
CGO_ENABLED=0 go build -gcflags "all=-N -l"
scp flowProbe fnii@172.171.50.61:~
ssh fnii@172.171.50.61 "lxc file push ~/flowProbe H1/root/"