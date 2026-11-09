FROM alpine:3.22
RUN apk add --no-cache nftables python3
CMD ["sh", "-c", "exec sleep infinity"]
