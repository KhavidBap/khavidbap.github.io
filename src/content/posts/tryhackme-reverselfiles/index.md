---
title: (VN) TryHackMe - Reversing ELF
published: 2025-11-18
description: 'Writeup cho tất cả các task trong room "Reversing ELF" trên platform TryHackMe.'
image: ''
tags: [Vietnamese, Reverse engineering]
category: 'TryHackMe'
draft: false 
lang: ''
---

# [Link to the room](https://tryhackme.com/room/reverselfiles)

# Crackme1

```cpp
//...
  char local_98 [32];
  uint local_78 [28];
  
  local_78[0] = 0x25;
  local_78[1] = 0x2b;
  //...
  local_78[0x18] = 0x25;
  local_78[0x19] = 0x3c;
  local_78[0x1a] = 0xffffffbf;

  memset(local_98, 0x41, 0x1b);
  for (local_78[0x1b] = 0; local_78[0x1b] < 0x1b; local_78[0x1b] = local_78[0x1b] + 1) {
    local_98[(int)local_78[0x1b]] =
        (char)local_78[(int)local_78[0x1b]] + local_98[(int)local_78[0x1b]];
  }
  puts(local_98);
//...
```

- `local_98` = 32-byte buffer, cài đặt `A [0x41]` lập lại `27 [0x1B]` lần.
- `local_78` = array gồm 27 số (từ `0` đến `0x1A`).
- `local_98[i] = (char)local_78[i] + local_98[i]`, hoặc `output[i] = 'A' + local_78[i]`.

```py
local_78 = [0x25, 0x2b, 0x20, 0x26, 0x3a, 0x2d, 0x2e, 0x33, 0x1e, 0x33,
            0x27, 0x20, 0x33, 0x1e, 0x2a, 0x28, 0x2d, 0x23, 0x1e, 0x2e,
            0x25, 0x1e, 0x24, 0x2b, 0x25, 0x3c]

print("".join(chr(0x41 + i) for i in local_78))
```

**What is the flag? - :spoiler[flag{not_that_kind_of_elf}]**

# Crackme2

```cpp
//...
  if (param_1 == 2)
    iVar2 = strcmp((char *)param_2[1],"<password>");
    if (iVar2 == 0) {
      puts("Access granted.");
      giveFlag();
      uVar1 = 0;
    }
//...
```

**What is the super secret password? - :spoiler[super_secret_password]**

```cpp
//...
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  char local_11f [51];
  undefined4 local_ec [51];
  uint local_20;

  puVar2 = &DAT_080486c0;
  puVar3 = local_ec;
  for (iVar1 = 0x33; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  memset(local_11f, 0x41, 0x33);
  for (local_20 = 0; local_20 < 0x33; local_20 = local_20 + 1) {
    local_11f[local_20] = (char)local_ec[local_20] + local_11f[local_20];
  }
//...
```

Dump data ở `DAT_080486c0` để lấy data cần được xử lý.

```
(gdb) x/204xb 0x080486c0
0x80486c0:      0x25    0x00    0x00    0x00    0x2b    0x00    0x00    0x00
0x80486c8:      0x20    0x00    0x00    0x00    0x26    0x00    0x00    0x00
0x80486d0:      0x3a    0x00    0x00    0x00    0x28    0x00    0x00    0x00
0x80486d8:      0x25    0x00    0x00    0x00    0x1e    0x00    0x00    0x00
0x80486e0:      0x28    0x00    0x00    0x00    0x1e    0x00    0x00    0x00
0x80486e8:      0x32    0x00    0x00    0x00    0x34    0x00    0x00    0x00
...
```

Vì mỗi giá trị ở `local_ec` được định dạng bằng `undefined4`, tức là mỗi phần tử đều có giá trị là 4 byte. Nên chúng ta chỉ cần lấy byte thấp nhất của mỗi giá trị integer này.

```py
byte = [0x25, 0x2b, 0x20, 0x26, 0x3a, 0x28, 0x25, 0x1e, 0x28, 0x1e, 
        0x32, 0x34, 0x21, 0x2c, 0x28, 0x33, 0x1e, 0x33, 0x27, 0x28, 
        0x32, 0x1e, 0x25, 0x2b, 0x20, 0x26, 0x1e, 0x33, 0x27, 0x24, 
        0x2d, 0x1e, 0x28, 0x1e, 0x36, 0x28, 0x2b, 0x2b, 0x1e, 0x26, 
        0x24, 0x33, 0x1e, 0x2f, 0x2e, 0x28, 0x2d, 0x33, 0x32, 0x3c]

print(''.join(chr(i + 0x41) for i in byte))
```

**What is the flag? - :spoiler[flag{if_i_submit_this_flag_then_i_will_get_points}]**

# Crackme3

```cpp
void processEntry entry(undefined4 param_1,undefined4 param_2) {
  undefined auStack_4 [4];
  __libc_start_main(FUN_080484f4, param_2,&stack0x00000004, FUN_08048d90, 
                    FUN_08048e00, param_1, auStack_4);
  do {} while( true );
}
```

Đọc function `FUN_080484f4` để lấy thêm thông tin.

```cpp
undefined4 FUN_080484f4(int param_1,undefined4 *param_2) {
    //...
    if ((sVar1 == 0x40) && (iVar2 = strcmp(__s_00,"<flag>"), iVar2 == 0)) {
        puts("Correct password!");
        return 0;
    }
    //...
}
```

**What is the flag? - :spoiler[f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5]**

# Crackme4

```cpp
undefined8 main(int param_1,undefined8 *param_2) {
  //...
  if (param_1 == 2) {
    compare_pwd((char *)param_2[1]);
  }
  //...
}
```

```cpp
void compare_pwd(char *param_1) {
    //...
    builtin_strncpy(local_28,"I]{I\x14V\x17{WAGQV\x17{TS@",0x13);
    get_pwd((long)local_28);
    iVar1 = strcmp(local_28,param_1);
    if (iVar1 == 0) {
        puts("password OK");
    }
    //...
}
```

String ở `local_28` bị mã hóa, đọc function `get_pwd()` để hiểu cách để đưa lại string ban đầu.

```cpp
void get_pwd(long param_1) {
  undefined4 local_c; 
  local_c = -1;
  while (local_c = local_c + 1, *(char *)(param_1 + local_c) != '\0') {
    *(byte *)(local_c + param_1) = *(byte *)(param_1 + local_c) ^ 0x24;
  }
}
```

Ở đây, mỗi kí tự trong `local_28` sẽ XOR với ký tự khác (`0x24`), từ đây viết lại code để in ra password.

```py
local_28 = b"I]{I\x14V\x17{WAGQV\x17{TS@"
decoded = bytes([i ^ 0x24 for i in local_28])
print(decoded.decode())
```

**What is the password? - :spoiler[my_m0r3_secur3_pwd]**

# Crackme5

```cpp
undefined8 main(void) {
  //...
  builtin_strncpy(local_38,"OfdlDSA|3tXb32~X3tX@sX`4tXtz",0x1c);
  puts("Enter your input:");
  __isoc99_scanf(&DAT_00400966,local_58);
  iVar1 = strcmp_(local_58,local_38);
  if (iVar1 == 0) {
    puts("Good game");
  }
  //...
}
```

Có một bug trong chương trình này, thay vì `strcmp()` thì họ đã sử dụng `strcmp_()`. Mặc dù vô hại nhưng cách xử lý của 2 function này là hoàn toàn khác nhau. Đọc thử function `strcmp_()` để hiểu cách hoạt động.

```cpp
void strcmp_(char *param_1, char *param_2) {
  //...
  while( true ) {
    sVar1 = strlen(param_1);
    if (sVar1 <= (ulong)(long)local_1c) break;
    param_1[local_1c] = (byte)key ^ param_1[local_1c];
    local_1c = local_1c + 1;
  }
  strncmp(param_1, param_2, 0x1c);
  return;
}
```

Có thể để ý ở đây mỗi ký tự được XOR với `key`. Xem thử `key` ở global có giá trị nào không.

```
(gdb) x/wx 0x601064
0x601064 <key>: 0x00000000
```

Vậy là xem như dãy kí tự ở `local_38` không bị mã hóa như kí tự ở input ban đầu.

**What is the input? - :spoiler[OfdlDSA|3tXb32~X3tX@sX`4tXtz]**

# Crackme6

```cpp
undefined8 main(int param_1,undefined8 *param_2) {
  if (param_1 == 2) {
    compare_pwd((char *)param_2[1]);
  }
  //...
}
```

```cpp
void compare_pwd(char *param_1) {
  //...
  uVar1 = my_secure_test(param_1);
  if ((int)uVar1 == 0) {
    puts("password OK");
  }
  //...
}
```

```cpp
undefined8 my_secure_test(char *param_1) {
  undefined8 uVar1;
  
  if ((*param_1 == '\0') || (*param_1 != '1')) {
    uVar1 = 0xffffffff;
  }
  else if ((param_1[1] == '\0') || (param_1[1] != '3')) {
    uVar1 = 0xffffffff;
  }
  //...
  else if ((param_1[7] == '\0') || (param_1[7] != 'd')) {
    uVar1 = 0xffffffff;
  }
  else if (param_1[8] == '\0') {
    uVar1 = 0;
  }
  else {
    uVar1 = 0xffffffff;
  }
  return uVar1;
}
```

Mỗi ký tự ở password là parameter cần nhập vào input để check xem password đó có đúng hay chưa.

**What is the password? - :spoiler[1337_pwd]**

# Crackme7

```cpp
undefined4 main(undefined param_1) {
    //...
    else if (local_14 == 0x7a69) {
        puts("Wow such h4x0r!");
        giveFlag();
    }
    //...
}
```

```cpp
void giveFlag(void) {
  //...
  puVar2 = &DAT_080488e0;
  puVar3 = local_a8;
  for (iVar1 = 0x22; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  memset(local_ca,0x41,0x22);
  for (local_20 = 0; local_20 < 0x22; local_20 = local_20 + 1) {
    local_ca[local_20] = (char)local_a8[local_20] + local_ca[local_20];
  }
  //...
}
```

Tới đây, cách xử lý quay về như bài [Crackme2](#crackme2).

```
(gdb) x/136xb 0x080488e0
0x80488e0:      0x25    0x00    0x00    0x00    0x2b    0x00    0x00    0x00
0x80488e8:      0x20    0x00    0x00    0x00    0x26    0x00    0x00    0x00
0x80488f0:      0x3a    0x00    0x00    0x00    0x2c    0x00    0x00    0x00
0x80488f8:      0x34    0x00    0x00    0x00    0x22    0x00    0x00    0x00
...
```

**What is the flag? - :spoiler[flag{much_reversing_very_ida_wow}]**

# Crackme8

```cpp
undefined4 main(int param_1,undefined4 *param_2) {
  //...
  if (param_1 == 2) {
    iVar2 = atoi((char *)param_2[1]);
    if (iVar2 == -0x35010ff3) {
      puts("Access granted.");
      giveFlag();
      uVar1 = 0;
    }
  }
  //...
}
```

Function `giveFlag()` hoàn toàn y chang với bài [Crackme2](#crackme2) và [Crackme7](#crackme7). Áp dụng các kỹ thuật đã được nêu ở 2 bài trên để ra được flag.

**What is the flag? - :spoiler[flag{at_least_this_cafe_wont_leak_your_credit_card_numbers}]**