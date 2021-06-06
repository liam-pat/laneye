# Scan Lan network

## Some network knowledge 

* Lan-network calculation. [Reference](https://blog.biyongyao.com/tech/ip-subnet-mask.html)

## Aim

1. Learn the network knowledge
2. Scan the local network to find other illegal machine
3. Use golang more Familiarly for developing.

## Use Method

```
#clone the responsity
git clone https://github.com/YaoMiss/go-lanscan.git

# build 
cd {{ DIR }}/src/main
go build 

# exec , the net interface maybe eth0
sudo ./main -I en0
```

## Todo
* Add the method to get all lan-network machines hostname
