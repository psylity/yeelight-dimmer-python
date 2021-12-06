# Python Yeelight YLKG07YL/YLKG08YL dimmer handler

## About

With this code you can handle dimmer changes in your python code. 
Just override `YeelightDimmer` class and implement your own handlers (check out the `demo.py` code)

Run the following to find out your dimmer MAC:
```
# hcitool lescan
LE Scan ...
F8:24:41:C5:A0:BE yee-rc
```
If you want to use Yeelight dimmers in your ESP32 project - check out [this repository](https://github.com/psylity/yeelight-dimmer-esp32)


## Demo

Retrieving beacon_key
```
# python3 demo.py F8:24:41:C5:A0:BE
using mac F8:24:41:C5:A0:BE
! Press the "Pair" button at the dimmer...
Connecting... done
Authenticating.. done
beacon_key: a3157ddfac2a30a7f5e33854
starting the demo. triple click to exit, single click to center the knob

[---------------|--------------0------------------------------] -15
```

Providing beacon_key

```
# python3 demo.py F8:24:41:C5:A0:BE a3157ddfac2a30a7f5e33854
using mac F8:24:41:C5:A0:BE
starting the demo. triple click to exit, single click to center the knob

[------------------------------0-----------------|------------] 018

```


