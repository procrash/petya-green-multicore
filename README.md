# petya_green
Application for a brute force attack on Green Petya's key
-
<b>This version works for the new updated green petya ransomware</b>

I forked this off from https://github.com/hasherezade/petya_green as the project seemed to only use one CPU core. 

In contrast to the original project I tried to improve the program in the following ways:
- Use C++ Boost to support multithreading on CPU
- Use the GPU to compute the keys
- Instead of trying a random key I try to search the whole key space whileas several threads handle different key space divisions independently
- The application has a graphical user interface now.

The GPU code is running and your keys are computed in less than three days on a Nvidia 980Ti graphics card. 

<pre>
Please respect the license of the source code and don't use this in a commercial context (see License.txt file). Coding takes time and effort.
As I'm not a student anymore and I don't share the flat with my parents I want of course some money back for the development of this application.
However I don't want to get rich of this as I don't want to behave the same way as the ransome developers. Therefore the code is open source here 
on GitHub and is free for everybody who is able to compile this. If you are not capable of doing that but still need help contact us on
https://petyaransomwarehilfe.wordpress.com

We're happy to help. A harddisk recovery costs 50 Euros. An engineering hour costs already more.
</pre>

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
3) Ctrl+C interrupts the key calculation.
If you want to resume it type:
<pre>
./petya_green --resume
</pre>
4) You can check the performance of your system and settings with
<pre>
./petya_green --performance
</pre>
