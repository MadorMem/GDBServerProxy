# Introduction  
Hi! This is a gdbserver in python, its currently used to remotely control ollydbg2 using gdb client elsewhere.  
This source code was taken from <https://github.com/0vercl0k/ollydbg2-python/tree/master/samples/gdbserver> that he/she took from/was inspired by <http://mspgcc.cvs.sourceforge.net/viewvc/mspgcc/msp430simu/gdbserver.py?revision=1.3&content-type=text%2Fplain> (if link is dead: <https://github.com/travisgoodspeed/msp430simu/blob/master/gdbserver.py>)  

The current purpose is to convert it to connect to a proprietary debugging interface via serial/telnet/ssh/etc so that a gdb client (IDA/gdb/etc) can connect and debug the product as if it had gdbserver running directly on it!.

The current goals are:  

- Rewrite it to be more generic so that it will be easier to implement an architecture/device.
	- Add vendor/device directory that in it there will be the device/vendor specific implementations (such as the serial/telnet/ssh debug commands, the connection and etc.)  
	- Write a device/vendor template that needs to be implemented for each device (using python ABC).  
	- Rewrite the main script so it will be generic so it will be able to recieve a device class and use it, no matter what device it is, and make sure that its tidy, clean and readable.  
	- Add launch parameters/etc so you'll be able to choose your device.  
	- Proper readme.  
- Make sure all gdb commands are implemented.  
	- Implement the commands that aren't.  

- Make sure the protocol is fully implemented and working, and that no corners were cut.  
  
## Please note  
As of right now, it's buggy and needs more work!  

# Further Reading  
<https://sourceware.org/gdb/current/onlinedocs/gdb/Packets.html>  
<https://sourceware.org/gdb/current/onlinedocs/gdb/Remote-Protocol.html>  
<https://www.embecosm.com/appnotes/ean4/embecosm-howto-rsp-server-ean4-issue-2.html>  
<https://www.google.com/search?q=gdb+rsp>  
  
# Original Creators/Forked From:  
<https://github.com/0vercl0k/ollydbg2-python/blob/master/samples/gdbserver/gdbserver.py>  
<https://github.com/travisgoodspeed/msp430simu/blob/master/gdbserver.py>  
  
