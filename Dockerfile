FROM scratch

CMD ["/pwned-serve"]

ENV FILTER_PATH=/pwned-data.bin

COPY pwned-serve pwned-data.bin /
