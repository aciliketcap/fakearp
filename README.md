Hi, fakeARP is a driver, written as a tutorial on developing Linux network drivers.

It is not connected to any hardware, it doesn't have a cable that connects it to outside world. But it pretends that it does and creates ARP responses when some ARP requests pass through, as if there are other network interfaces on the other side of the cable.

I wrote it to learn about writing network drivers but as it turns out there is not so much info on the internet about that. I was reading Linux Device Drivers - Third Edition which I downloaded from LWN.net and realized that a lot has changed in network subsystem of Linux. I think it will be valuable for anyone who read the book (or other stuff out-dated as far as the network subsystem goes) and wants to catch up with current network code.

The comments inside the code should be enough for anyone who developed drivers before but I will be writing a more detailed tutorial on the code. I will add a link to that as soon as I write it. 

Since the code is meant to be a tutorial it is quite poor when it comes to features. Its flaws are described in the beginning of the code. Also I didn't introduce anything related to rtnl/netlink, anyone curious about that subject can look at bridge driver code inside Linux source and brctl utility.

I am using a seperate test kernel which runs on a VM as development environment. If you are doing so, you should write that seperate kernel's include dir in Makefile, change the link kerneldir to that kernel source and write the path of fake ARP source inside farmake.script. After that running fakearp.script should compile your driver. If you want to compile for the running kernel just type 'make'. I compiled and tested the driver using Gentoo and 3.14.59 kernel.

Under any circumstances it should not be run on a production system. I am a newbie at developing kernel code and this is the very first network driver code I have ever written. As a side note please send me any bugs you encounter.

Finally this distribution of code is licensed under GNU General Public License version 2. Fake ARP driver is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details. You should have received a copy of it in a file named LICENSE, if not see (http://www.gnu.org/licenses/).

Hope it helps anyone trying to learn about network drivers,
Sinan


