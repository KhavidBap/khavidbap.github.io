---
title: (EN) PatriotCTF 2025 - Reverse
published: 2025-11-22
description: 'Writeup for all Reverse Engineering challenge in PatriotCTF 2025 by VGU_Cypher'
image: ''
tags: [English, Reverse engineering]
category: 'Writeup'
draft: false 
lang: ''
---

# Space Pirates

```cpp
...

#define FLAG_LEN 30
const uint8_t TARGET[FLAG_LEN] = {...};

// The pirate's rotating XOR key
const uint8_t XOR_KEY[5] = {0x42, 0x73, 0x21, 0x69, 0x37};

// The magic addition constant
const uint8_t MAGIC_ADD = 0x2A;
// PCTF{0x_M4rks_tH3_sp0t_M4t3y}

...
```

Yea, they wrote the right flag inside the file, how hilarious it is.

**Flag: :spoiler[pctf{0x_M4rks_tH3_sp0t_M4t3y}]**

# Are You Pylingual?

We're giving `.pyc` file. Decompile it and we have this code:

```py
import pyfiglet
file = open('flag.txt', 'r')
flag = file.read()
font = 'slant'
words = 'MASONCC IS THE BEST CLUB EVER'
flag_track = 0
art = list(pyfiglet.figlet_format(words, font=font))
i = len(art) % 10
for ind in range(len(art)):
    if ind == i and flag_track < len(flag):
        art[ind] = flag[flag_track]
        i += 28
        flag_track += 1
art_str = ''.join(art)
first_val = 5
second_val = 6
first_half = art_str[:len(art_str) // 2]
second_half = art_str[len(art_str) // 2:]
first = [~ord(char) ^ first_val for char in first_half]
second = [~ord(char) ^ second_val for char in second_half]
output = second + first
print(output)
```

Basically, the generator split the figlet output `art_str` into 2 parts, `first_half` (`floor(L / 2)`) and `second_half`. It encoded as:
```py
first = [ord(char) ^ first_val for char in first_half]
second = [ord(char) ^ second_val for char in second_half]
```
then printed `output = second + first`.

So to decode this, we need to split the provided `output` list into `second` (length = `ceil(len(output) / 2)`) and `first` (length = `floor(len(output) / 2)`). Then, recover bytes with `ord = (~(v ^ val)) & 0xFF` and `chr(ord)` to print it out.

```py
from pyfiglet import figlet_format

output = [...]
first_val = 5
second_val = 6

L = len(output)
first_len = L // 2         # = floor(L / 2)
second_len = L - first_len # = ceil(L / 2)
second_enc = output[:second_len]
first_enc  = output[second_len:]

def decode_list(enc_list, val):
    chars = []
    for v in enc_list:
        o = (~(v ^ val)) & 0xFF
        chars.append(chr(o))
    return ''.join(chars)

first_half = decode_list(first_enc, first_val)
second_half = decode_list(second_enc, second_val)
art_str = first_half + second_half
print(art_str[:1000])
```

Run this and it would print out the ASCII art with some characters from the flag.

```
  p __  ______   _____ ____  _c  ______________   ________t
   /  |/  /   | / ___// __f\/ | / / ____/ ____/  /  _/{___/
  / /|_/ / /| | \__ \/o/ / /  |/ / /   / /       /b/ \__ \
 / /  / / ___ |___F / /_/ / /|  / /___/ /___  u_/ / ___/ /
/_/  /_/_/  |_s____/\____/_/ |_/\____/\___c/  /___//____/
          4                           t
  ____i___  ________   ____  _____0___________   ________    _n  ______
 /_  __/ / / / ____/  / __ )/ ____/ ___/_  __i  / ____/ /   / / / / __ )
5 / / / /_/ / __/    / __  /n__/  \__ \ / /    / /   / /'  / / / / __  |
 / / / __  t /___   / /_/ / /___ ___/ /_ /    / /___/ /___/ /_/ / /E/ /
/_/ /_/ /_/_____/  /__n__/_____//____//_/     \___c/_____/\____/_____/
     R                           y                           p
    _______    _t__________
   / ____/ |  /1/ ____/ __ \
  / __/  | | /o/ __/ / /_/ /
 / /___  | |/N/ /___/ _, _/
/_____/  |__}/_____/_/ |_|
```

**Flag: :spoiler[pctf{obFusc4ti0n_i5n't_EncRypt1oN}]**

# Space Pirates 2

```rs {88-94}
use std::env;
use std::process;

const TARGET: [u8; 32] = [0x15, 0x5A, 0xAC, 0xF6, 0x36, 0x22, 0x3B, 0x52, 0x6C, 0x4F, 0x90, 0xD9, 0x35, 0x63, 0xF8, 0x0E, 0x02, 0x33, 0xB0, 0xF1, 0xB7, 0x69, 0x42, 0x67, 0x25, 0xEA, 0x96, 0x63, 0x1B, 0xA7, 0x03, 0x0B];
const XOR_KEY: [u8; 5] = [0x7E, 0x33, 0x91, 0x4C, 0xA5];
const ROTATION_PATTERN: [u32; 7] = [1, 3, 5, 7, 2, 4, 6];
const MAGIC_SUB: u8 = 0x5D;

fn print_flag(buffer: &str) {
    println!("Flag: {0}\n", buffer);
}

/// Rotate a byte left by n positions
/// This is a bijection because all 8 bit rotations of a byte are unique
/// ROL(ROL(x, n), 8-n) = x, proving invertibility
fn rotate_left(byte: u8, n: u32) -> u8 {
    byte.rotate_left(n % 8)
}

/// OPERATION 1: XOR with NEW rotating key
/// Each byte is XORed with one of 5 NEW key bytes (cycling through them)
/// Bijection proof: (x ⊕ k) ⊕ k = x (XOR involution)
fn apply_quantum_cipher_v2(buffer: &mut [u8]) {
    for (i, byte) in buffer.iter_mut().enumerate() {
        *byte ^= XOR_KEY[i % 5];
    }
}

/// OPERATION 2 (NEW!): Rotate Left with varying amounts
/// Each byte is rotated left by an amount determined by its position
/// Bijection proof: ROL⁻¹ = ROR with same amount
/// The rotation amount varies: position mod 7 selects from ROTATION_PATTERN
fn apply_stellar_rotation(buffer: &mut [u8]) {
    for (i, byte) in buffer.iter_mut().enumerate() {
        let rotation = ROTATION_PATTERN[i % 7];
        *byte = rotate_left(*byte, rotation);
    }
}

/// OPERATION 3: Swap adjacent byte pairs
/// Bytes at positions (0,1), (2,3), (4,5), etc. are swapped
/// Bijection proof: Swapping twice returns original (f ∘ f = identity)
fn apply_spatial_transposition(buffer: &mut [u8]) {
    for i in (0..buffer.len()).step_by(2) {
        buffer.swap(i, i + 1);
    }
}

/// OPERATION 4: Subtract magic constant (mod 256) - CHANGED FROM ADDITION!
/// Each byte has MAGIC_SUB subtracted from it (wrapping at 256)
/// Bijection proof: (x - k) + k ≡ x (mod 256)
/// Subtraction forms a group, every element has unique inverse
fn apply_gravitational_shift_v2(buffer: &mut [u8]) {
    for byte in buffer.iter_mut() {
        *byte = byte.wrapping_sub(MAGIC_SUB);
    }
}

/// OPERATION 5 (NEW!): Reverse bytes in chunks of 5
/// Splits the 30-byte buffer into 6 chunks of 5, reverses each chunk
/// Chunk 0: [0,1,2,3,4] -> [4,3,2,1,0]
/// Chunk 1: [5,6,7,8,9] -> [9,8,7,6,5], etc.
/// Bijection proof: Reversal is self-inverse, f(f(x)) = x
fn apply_temporal_inversion(buffer: &mut [u8]) {
    const CHUNK_SIZE: usize = 5;
    for chunk_start in (0..buffer.len()).step_by(CHUNK_SIZE) {
        let chunk_end = (chunk_start + CHUNK_SIZE).min(buffer.len());
        buffer[chunk_start..chunk_end].reverse();
    }
}

/// OPERATION 6 (NEW!): XOR each byte with its position SQUARED (mod 256)
/// Byte at position i is XORed with i² mod 256
/// Bijection proof: (x ⊕ k) ⊕ k = x (XOR involution)
/// While i² grows, mod 256 keeps values in range, and XOR remains invertible
fn apply_coordinate_calibration_v2(buffer: &mut [u8]) {
    for (i, byte) in buffer.iter_mut().enumerate() {
        let position_squared = ((i * i) % 256) as u8;
        *byte ^= position_squared;
    }
}

fn process_transmission(input: &str) -> Result<[u8; 32], String> {
    if input.len() != 32 {
        return Err(format!(input.len()));
    }
    let mut buffer = [0u8; 32];
    buffer.copy_from_slice(input.as_bytes());
    apply_quantum_cipher_v2(&mut buffer);
    apply_stellar_rotation(&mut buffer);
    apply_spatial_transposition(&mut buffer);
    apply_gravitational_shift_v2(&mut buffer);
    apply_temporal_inversion(&mut buffer);
    apply_coordinate_calibration_v2(&mut buffer);
    Ok(buffer)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        process::exit(1);
    }

    let input = &args[1];
    match process_transmission(input) {
        Ok(buffer) => {
            if buffer == TARGET {
                print_flag(input);
            } else {
                println!("\n");
                process::exit(1);
            }
        }
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        }
    }
}
```

The pipeline for the encryption, from input to flag, is:
1. XOR with rotating key
2. Rotate left with varying amounts
3. Swap adjacent byte pairs
4. Subtract magic constant
5. Reverse bytes in chunks of 5
6. XOR each byte with its position squared

So, we need to undo these steps, from operation 6 back to 1, to get the orginal flag. Simple.

```py
TARGET = [0x15, 0x5A, 0xAC, 0xF6, 0x36, 0x22, 0x3B, 0x52, 0x6C, 0x4F, 0x90, 0xD9, 0x35, 0x63, 0xF8, 0x0E, 0x02, 0x33, 0xB0, 0xF1, 0xB7, 0x69, 0x42, 0x67, 0x25, 0xEA, 0x96, 0x63, 0x1B, 0xA7, 0x03, 0x0B]
XOR_KEY = [0x7E, 0x33, 0x91, 0x4C, 0xA5]
ROTATION_PATTERN = [1, 3, 5, 7, 2, 4, 6]
MAGIC_SUB = 0x5D

def ror(byte, n):
    n %= 8
    return ((byte >> n) | ((byte << (8 - n)) & 0xFF)) & 0xFF

def solve():
    buf = TARGET.copy()
    # Operation 6
    for i in range(32):
        buf[i] ^= (i * i) % 256
    # Operation 5
    for cs in range(0, 32, 5):
        buf[cs:cs+5] = reversed(buf[cs:cs+5])
    # Operation 4
    for i in range(32):
        buf[i] = (buf[i] + MAGIC_SUB) & 0xFF
    # Operation 3
    for i in range(0, 32, 2):
        buf[i], buf[i+1] = buf[i+1], buf[i]
    # Operation 2
    for i in range(32):
        rot = ROTATION_PATTERN[i % 7]
        buf[i] = ror(buf[i], rot)
    # Operation 1
    for i in range(32):
        buf[i] ^= XOR_KEY[i % 5]
    s = bytes(buf).decode("utf-8")
    print("Recovered input:")
    print(s)

if __name__ == "__main__":
    solve()
```

**Flag: :spoiler[pctf{Y0U_F0UND_TH3_P1R4T3_B00TY}]**

# Space Pirates 3

```go {69-74}
package main
import (
	"fmt"
	"os"
)
var target = [30]byte{
	0x60, 0x6D, 0x5D, 0x97, 0x2C, 0x04, 0xAF, 0x7C, 0xE2, 0x9E, 0x77, 0x85, 0xD1, 0x0F, 0x1D, 0x17, 0xD4, 0x30, 0xB7, 0x48, 0xDC, 0x48, 0x36, 0xC1, 0xCA, 0x28, 0xE1, 0x37, 0x58, 0x0F,
}
var xorKey = [7]byte{0xC7, 0x2E, 0x89, 0x51, 0xB4, 0x6D, 0x1F}
var rotationPattern = [8]uint{7, 5, 3, 1, 6, 4, 2, 0}
const magicSub byte = 0x93
const chunkSize = 6

func printFlag(input string) {
	fmt.Println("Flag: ", input)
}
func rotateLeft(b byte, n uint) byte {
	n = n % 8
	return (b << n) | (b >> (8 - n))
}
func applyUltimateQuantumCipher(buffer []byte) {
	for i := range buffer {
		buffer[i] ^= xorKey[i%len(xorKey)]
	}
}
func applyStellarRotationV2(buffer []byte) {
	for i := range buffer {
		rotation := rotationPattern[i%len(rotationPattern)]
		buffer[i] = rotateLeft(buffer[i], rotation)
	}
}
func applySpatialTransposition(buffer []byte) {
	for i := 0; i < len(buffer)-1; i += 2 {
		buffer[i], buffer[i+1] = buffer[i+1], buffer[i]
	}
}
func applyGravitationalShiftV3(buffer []byte) {
	for i := range buffer {
		buffer[i] -= magicSub
	}
}
func applyTemporalInversionV2(buffer []byte) {
	for chunkStart := 0; chunkStart < len(buffer); chunkStart += chunkSize {
		chunkEnd := chunkStart + chunkSize
		if chunkEnd > len(buffer) {
			chunkEnd = len(buffer)
		}
		for i, j := chunkStart, chunkEnd-1; i < j; i, j = i+1, j-1 {
			buffer[i], buffer[j] = buffer[j], buffer[i]
		}
	}
}
func applyCoordinateCalibrationV3(buffer []byte) {
	for i := range buffer {
		positionValue := ((i * i) + i) % 256
		buffer[i] ^= byte(positionValue)
	}
}

func processVault(input string) ([30]byte, error) {
	var result [30]byte
	if len(input) != 30 {
		return result, fmt.Errorf(
			"Invalid vault combination",
		)
	}
	copy(result[:], input)
	buffer := result[:]
	applyUltimateQuantumCipher(buffer)
	applyStellarRotationV2(buffer)
	applySpatialTransposition(buffer)
	applyGravitationalShiftV3(buffer)
	applyTemporalInversionV2(buffer)
	applyCoordinateCalibrationV3(buffer)
	return result, nil
}

func main() {
	if len(os.Args) != 2 {
		os.Exit(1)
	}
	input := os.Args[1]
	result, err := processVault(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, " %v\n", err)
		os.Exit(1)
	}
	if result == target {
		printFlag(input)
	} else {
		fmt.Println("\n")
		os.Exit(1)
	}
}
```

Different programming language, but have the same meaning in each operation, the same as [Sapce Pirates 2](#space-pirates-2). So, to reverse it, we need to:
1. XOR each byte with `(i^2 + i) mod 256`
2. Reverse each 6-byte chunk
3. Add `magicSub`
4. Swap adjacent pairs
5. Rotate right by the rotation pattern
6. XOR with 7-byte `xorKey`

```py
TARGET = [0x60, 0x6D, 0x5D, 0x97, 0x2C, 0x04, 0xAF, 0x7C, 0xE2, 0x9E, 0x77, 0x85, 0xD1, 0x0F, 0x1D, 0x17, 0xD4, 0x30, 0xB7, 0x48, 0xDC, 0x48, 0x36, 0xC1, 0xCA, 0x28, 0xE1, 0x37, 0x58, 0x0F]
XOR_KEY = [0xC7, 0x2E, 0x89, 0x51, 0xB4, 0x6D, 0x1F]
ROTATION_PATTERN = [7, 5, 3, 1, 6, 4, 2, 0]
MAGIC_SUB = 0x93

def ror(byte, n):
    n %= 8
    return ((byte >> n) | ((byte << (8 - n)) & 0xFF)) & 0xFF

def solve():
    buf = TARGET.copy()
    # Operation 6
    for i in range(30):
        buf[i] ^= ((i * i) + i) % 256
    # Operation 5
    for cs in range(0, 30, 6):
        buf[cs:cs+6] = reversed(buf[cs:cs+6])
    # Operation 4
    for i in range(30):
        buf[i] = (buf[i] + MAGIC_SUB) & 0xFF
    # Operation 3
    for i in range(0, 30, 2):
        buf[i], buf[i+1] = buf[i+1], buf[i]
    # Operation 2
    for i in range(30):
        rot = ROTATION_PATTERN[i % 8]
        buf[i] = ror(buf[i], rot)
    # Operation 1
    for i in range(30):
        buf[i] ^= XOR_KEY[i % 7]
    s = bytes(buf).decode("utf-8")
    print("Recovered input:")
    print(s)

if __name__ == "__main__":
    solve()
```

**Flag: :spoiler[pctf{M4ST3R_0F_TH3_S3V3N_S34S}]**

# Vorpal Masters

```cpp
void main(void) {
  int iVar1;
  int local_20;
  char local_1c [11];
  char local_11;
  char local_10;
  char local_f;
  char local_e;
  int local_c;
  
  puts("Welcome to {insert game here}\nPlease enter the license key from the 3rd page of the booklet.");
  local_c = __isoc99_scanf("%4s-%d-%10s", &local_11, &local_20, local_1c);
  if (local_c != 3) {
    puts("Please enter you key in the format xxxx-xxxx-xxxx");
    exit(0);
  }
  if ((((local_11 != 'C') || (local_f != 'C')) || (local_e != 'I')) || (local_10 != 'A')) {
    womp_womp();
  }
  if ((-0x1389 < local_20) && (local_20 < 0x2711)) {
    if ((local_20 + 0x16) % 0x6ca == ((local_20 * 2) % 2000) * 6 + 9) goto LAB_00101286;
  }
  womp_womp();
LAB_00101286:
  iVar1 = strcmp(local_1c, "PatriotCTF");
  if (iVar1 != 0) womp_womp();
  puts("Lisence key registered, you may play the game now!");
  return;
}
```

The key is in the form `xxxx-xxxx-xxxx`. In `local_c`, it decleares that `local_c = __isoc99_scanf("%4s-%d-%10s", &local_11, &local_20, local_1c);`, meaning there are 3 parts in the key:
1. First part is a string having 4 characters;
2. Second part is a number;
3. Third part is a string having 10 characters.

- For the first part, although the arrangement in the code was wrong (`CCIA`), but based on the memory of each variable, we know that the first part is `CACI` (like what the challenge statement said).

- For the second part, we know that:
```cpp
  if ((-0x1389 < local_20) && (local_20 < 0x2711)) {
    if ((local_20 + 0x16) % 0x6ca == ((local_20 * 2) % 2000) * 6 + 9) goto LAB_00101286;
  }
```
which means:
```py
for n in range(-4999, 10000):
    if (n + 22) % 1738 == ((n * 2) % 2000) * 6 + 9:
        print(n) # goto LAB_00101286;
```
So the second part is `2025`.

- For the third part, we already know it is `PatriotCTF`.

**Flag: :spoiler[CACI{2025-PatriotCTF}]**