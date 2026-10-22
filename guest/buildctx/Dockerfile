# lx build in the suite: ARG/ENV expansion, WORKDIR, COPY (+ --chown, + .dockerignore), RUN (files
# added and deleted, a user created), USER, ENTRYPOINT + CMD.
FROM alpine:latest
ARG FLAVOR=plain
ENV GREETING="hello from" \
    APP=/srv/app
WORKDIR $APP
COPY hello.sh ./
COPY --chown=nobody:nogroup hello.sh /tmp/owned.sh
COPY . /ctx
RUN test -e /ctx/hello.sh && test ! -e /ctx/ignored.txt && test ! -e /ctx/logs/build.log # .dockerignore
RUN echo "$FLAVOR" > flavor && rm /etc/motd && adduser -D builder
USER builder
ENTRYPOINT ["sh", "hello.sh"]
CMD ["lx build"]
