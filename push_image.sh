#!/bin/bash

set -xe

Version=$1
ImageId=`docker images | grep judge_server | grep ${Version} | grep -v /judge_server | awk '{print $3}'`

docker login --username=ashentoo registry.cn-hangzhou.aliyuncs.com -p a1806996288
docker tag ${ImageId} registry.cn-hangzhou.aliyuncs.com/ashentoo/judge_server:${Version}
docker push registry.cn-hangzhou.aliyuncs.com/ashentoo/judge_server:${Version}