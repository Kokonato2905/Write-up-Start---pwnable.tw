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

Khi đọc kĩ vào decompile, ta có thể thấy được cách hoạt động của chương trình:
- Đẩy giá trị esp vào stack (push esp)
- Đẩy địa chỉ hàm thoát vào stack để kết thúc chương trình khi gọi return (push offset _exit)
- Reset lại giá trị của các register eax, ebx, ecx, edx về 0 (các lệnh xor)
- Lần lượt đẩy dòng chữ "Let's start the CTF:" vào stack. (5 lần push ngay dưới)
- Phát ngắt đầu tiên (int 80h), gọi hàm write (eax = 4) để in vào stdout (ebx = 1) 20 kí tự (edx = 0x14) tại địa chỉ esp (ecx = esp), mục đích là in dòng ‘Let’s start the CTF:’ ra màn hình
- Phát ngắt thứ hai, gọi hàm read (eax = 3) để đọc tối đa 60 kí tự (edx = 0x3c) từ stdin (ebx = 0) (tức từ bàn phím), lưu vào stack tại vị trí esp (ecx = esp).
- Tăng giá trị esp lên 20 (để esp chỉ lại vào hàm exit) và return
