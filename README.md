# Scan Lan network

## Aim

1. Learn the network knowledge
2. Scan the local network to find other illegal machine
3. Familiar use goland for developing.

## Use Method

```
# init the go mod
cd {{ DIR }}
go mod init

# build 
cd {{ DIR }}/src/main
go build 

# exec , the net interface maybe eth0
sudo ./main -I en0
```

## Development

* It is still developing
