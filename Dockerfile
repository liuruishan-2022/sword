FROM xwharbor.wxchina.com/cpaas/component/ubuntu:24.10

COPY ../target/release/sword /opt

WORKDIR /opt

ENTRYPOINT ["/opt/sword"]