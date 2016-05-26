# petya_green
Application for random attack on Green Petya's key
-
<b>WARNING!</b> This is just an experiment! 
Efficiency of this application is much, much lower than the previous solution (for Red Petya).
I am making it available for the people who want to participate in the experiment of unlocking Green Petya - due to the fact that the previous solution does not work at all.

I forked this off from https://github.com/hasherezade/petya_green as the project seemed to only use one CPU core. 

In contrast to the original project I tried to improve the program in the following ways:
- Use C++ Boost to support multithreading on CPU
- Use the GPU to compute the keys
- Instead of trying a random key I try to search the whole key space whileas several threads handle different key space divisions independently

However, the code is still under heavy development and definitely needs some cleanup and further improvements.
The GPU code is running now but it lacks on performance. As I just started with CUDA I still don't know yet how to achieve further performance.

I also don't know if the code that I've written contains some errors. So if somebody of you has a clue where to get a fresh petya-green malware I'd like to have a copy to check if the code is working
Drop me a mail with a link where I can pull it (don't send it please) to p r o c r a s h at n e u s o b dot de.

Or even better if you know a key and have an encrypted sector available this would even be better. 

<b>USAGE</b><br/>
1) If you have a key and you want to test it:<br/>
<pre>
./petya_green [disk dump] [key]
</pre>
Example:
<pre>
./petya_green disk_fragment.bin nGuJGbmDuVN9XmLa
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
2) If you don't have a key and you want to search it:
<pre>
./petya_green [disk dump] [key]
</pre>
Example:
<pre>
./petya_green disk_fragment.bin
[+] Petya bootloader detected!
[+] Petya http address detected!
[+] Petya FOUND on the disk!
---
verification data:
34 80 15 1a d1 76 5c 7b 60 2b e3 d0 d0 ae f8 c2 

nonce:
07 0c 12 f6 79 28 73 cb 
---
The key will be random!
Please wait, searching key is in progress...
</pre>
