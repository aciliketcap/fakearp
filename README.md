Hi, fakeARP is a driver, written as a tutorial on developing Linux network drivers.

It creates and interface and that interface forges fake ARP responses when some ARP requests pass throughit, as if there are other network interfaces connected to it.

I wrote it to learn about writing network drivers. I hope it helps other people trying to understand Linux kernel's network subsystem. The comments inside the code should be enough for anyone who developed drivers before but I will be writing a more detailed tutorial on the code. I will add a link to that as soon as I write it. 

Since the code is meant to be a tutorial it is quite poor when it comes to features. Its flaws are described in the beginning of the code. Also I didn't introduce anything related to rtnl/netlink, anyone curious about that subject can look at bridge driver code inside Linux source and brctl utility.

My development environment consists of seperate test kernel which runs on a VM. If you are doing so, you should write that seperate kernel's include dir in Makefile, change the link "kerneldir" to that kernel source and write the path of fake ARP source inside farmake.script. After that running fakearp.script should compile your driver relative to the seperate kernel you are using. 

If you want to compile for the running kernel just type 'make'. 

I developing the driver using 3.12.x kernel series.

Under any circumstances this code should not be run on a production system. I am a newbie at developing kernel code and this is the very first network driver code I have ever written. 

Please send me any bugs you encounter.

Finally this distribution of code is licensed under GNU General Public License version 3. Fake ARP driver is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details. You should have received a copy of it in a file named LICENSE, if not see (http://www.gnu.org/licenses/).

Hope it helps anyone trying to learn about Linux network drivers,
Sinan


