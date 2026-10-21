# lx build in the suite: ARG/ENV expansion, WORKDIR, COPY (+ --chown), RUN (files added and deleted,
# a user created), USER, ENTRYPOINT + CMD.
FROM alpine:latest
ARG FLAVOR=plain
ENV GREETING="hello from" \
    APP=/srv/app
WORKDIR $APP
COPY hello.sh ./
COPY --chown=nobody:nogroup hello.sh /tmp/owned.sh
RUN echo "$FLAVOR" > flavor && rm /etc/motd && adduser -D builder
USER builder
ENTRYPOINT ["sh", "hello.sh"]
CMD ["lx build"]
