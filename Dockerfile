FROM ubuntu:18.04

COPY build/java_policy /etc
RUN sed -E -i -e 's/(archive|ports).ubuntu.com/mirrors.aliyun.com/g' -e '/security.ubuntu.com/d' /etc/apt/sources.list
ENV DEBIAN_FRONTEND=noninteractive
RUN buildDeps='software-properties-common git libtool cmake python-dev python3-pip python-pip libseccomp-dev curl' && \
    apt-get update && apt-get install -y python python3 python-pkg-resources python3-pkg-resources $buildDeps && \
    add-apt-repository ppa:ubuntu-toolchain-r/test && \
    apt-get update && apt-get install -y  gcc-9 g++-9 swig && \
    update-alternatives --install  /usr/bin/gcc gcc /usr/bin/gcc-9 90 && \
    update-alternatives --install  /usr/bin/g++ g++ /usr/bin/g++-9 90 && \
    pip3 install -i https://mirrors.aliyun.com/pypi/simple/ -I --no-cache-dir psutil gunicorn flask requests idna && \
    cd /tmp && git clone -b newnew  --depth 1 https://github.com/Ashen-twos/Judger.git && cd Judger && \
    mkdir build && cd build && cmake .. && make && make install && cd ../bindings/Python && python3 setup.py install && \
    mkdir -p /code && \
    cd /code && git clone https://github.com/Ashen-twos/ExtraJudger.git && cd ExtraJudger && bash build.sh && \
#    apt-get purge -y --auto-remove $buildDeps && \
#    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    useradd -u 12001 compiler && useradd -u 12002 code && useradd -u 12003 spj && usermod -a -G code spj
HEALTHCHECK --interval=5s --retries=3 CMD python3 /code/service.py
ADD server /code
WORKDIR /code
RUN gcc -shared -fPIC -o unbuffer.so unbuffer.c
EXPOSE 8080
ENTRYPOINT /code/entrypoint.sh
