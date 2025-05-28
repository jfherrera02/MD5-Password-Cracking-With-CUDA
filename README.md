# MD5-Password-Cracking-With-CUDA

This project is a GPU-accelerated MD5 password cracker written in C++ with CUDA. It takes a target MD5 hash and compares it against millions of candidate passwords from a wordlist to find the original plaintext password (if it exists). Each GPU thread hashes one password and checks if it matches the target.

I also wrote a sequential version of the cracker to compare runtime performance. The CUDA version showed massive speedups (15x~), especially when testing large datasets like 100 million or more passwords.

I used the RockYou wordlist for testing and measured the time for both file reading and GPU hashing. This was a great learning experience for understanding parallel programming, memory allocation, and performance profiling with CUDA.

# Results
<img src="https://github.com/jfherrera02/MD5-Password-Cracking-With-CUDA/blob/main/images/CUDA-crack.png?raw=true" alt="CUDA password cracking output" width="650"/>
