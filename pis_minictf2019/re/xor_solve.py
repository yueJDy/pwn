str = [0x6d, 0x69, 0x6e, 0x69, 0x43, 0x54, 0x46, 0x7b]
xor = [0x5d, 0x1c, 0x3a, 0x26, 0x25, 0x36, 0x29, 0x3,
		0x4,0x6,0x0b,0x7e,0x56,0x0c,0x8,0x27,0x51,0x26,
		0x0b,0x36,0x29,0x17,0x30,0x20,0x0,0x7,0x0b,0x2,
		0x55,0x3d,0x18,0x31,0x44,0x1d,0x0b,0x24,0x3,0x1b,
		0x30,0x19,0x7e,0x11,0x0b,0x2b,0x56,0x0c,0x1b,0x27,
		0x52,0x7,0x21,0x1b,0x55,0x4,0x5f,0x0a,0x53,0x10,
		0x27,0x10,0x56,0x1a,0x58,0x1e,0x4,0x41,0x35,0x7e,0x56,0x1f]
flag = []
for i in range(0,8):
	x = str[i] ^ xor[i]
	flag.append(x)

print flag
key = []

for i in range(0,70):
	j = i%8
	key.append(flag[j])

print len(key)
print key

flag = []
for i in range(0,70):
	x = key[i] ^ xor[i]
	flag.append(x)
print flag