# petya_green
Application for a brute force attack on Green Petya's key
-
<b>This version works for the new updated green petya ransomware</b>

I forked this off from https://github.com/hasherezade/petya_green as the project seemed to only use one CPU core. 

In contrast to the original project I tried to improve the program in the following ways:
- Use C++ Boost to support multithreading on CPU
- Use the GPU to compute the keys
- Instead of trying a random key I try to search the whole key space whileas several threads handle different key space divisions independently

The GPU code is running and your keys are computed in less than three days on a Nvidia 980Ti graphics card. 

AGE: petya_green [] [--help] [--version] [--gpu] [--cpu] [--resume] [--random] [--selftest] [--performance] [--queryDeviceInfo] [--file ARG] [--key ARG] [--cpu_threads ARG] [--gpu_threads ARG] [--gpu_blocks ARG] [--gpu_keysCtxSwitch ARG] [--start_key ARG] [--nrOfKeysToCalculate ARG] 

Option Arguments: 
	--help              	display help message
	--version           	output the version number
	--file              	filename which contains disk dump of crypted harddrive (does only need to be the first 57 sectors)
	--gpu               	keys are calculated on gpu (notice if you specify both option gpu and cpu is used to calculute the keys)
	--cpu               	keys are calculated on cpu
	--resume            	resume previous calculation
	--random            	use a random key instead of brute force mothod, notice this doesn't allow a resume as wrong keys are not stored
	--key               	try a specific key
	--selftest          	check if algorithms work
	--performance       	provide information about performance
	--cpu_threads       	nr of threads to use on CPU for CPU calculation
	--queryDeviceInfo   	Displays information about NVIDIA devices
	--gpu_threads       	number of threads to use on GPU
	--gpu_blocks        	number of blocks to use on GPU
	--gpu_keysCtxSwitch 	number keys which are calculated on a the gpu before the context switches back to host
	--start_key         	start key number (defaults to 0)
	--nrOfKeysToCalculate	nr of keys which should be calculated before program ends [defaults to all key combinations (2*26+10)^8]


1) If you have a key and you want to test it:<br/>
<pre>
./petya_green [disk dump] [key]
</pre>
Example:
<pre>
./petya_green --key nGuJGbmDuVN9XmLa disk_fragment.bin 
[+] Petya bootloader detected!
[+] Petya http address detected!
[+] Petya FOUND on the disk!
---
verification data:
34 80 15 1a d1 76 5c 7b 60 2b e3 d0 d0 ae f8 c2 

nonce:
07 0c 12 f6 79 28 73 cb 
---

decoded data:
07 07 07 07 07 07 07 07 07 07 07 07 07 07 07 07 

[+] nGuJGbmDuVN9XmLa is a valid key
</pre>
2) If you don't have a key and you want to search it add either --cpu or --gpu in the command line options:
<pre>
./petya_green [disk dump] [key]
</pre>
Example:
<pre>
./petya_green disk_fragment.bin --gpu
[+] Petya bootloader detected!
[+] Petya http address detected!
[+] Petya FOUND on the disk!
---
verification data:
34 80 15 1a d1 76 5c 7b 60 2b e3 d0 d0 ae f8 c2 

nonce:
07 0c 12 f6 79 28 73 cb 
---
Please wait, searching key is in progress...
</pre>
<pre>
Ctrl+C interrupts the key calculation.

If you want to resume it type:
./petya_green --resume
</pre>
