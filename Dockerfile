FROM scratch

CMD ["/pwned-serve"]

ENV FILTER_PATH=/pwned-data.bin

USER 1000:1000

COPY pwned-serve pwned-data.bin /
