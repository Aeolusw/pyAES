from .galois_field import GF8


# from galois_field import GF8


class AESCipher:
    Nk = 4  # length of key in 32-bit words
    Nb = 4  # length of block in 32-bit words
    Nr = 10  # number of rounds

    def __init__(self, key_text, mode, iv_text, padding="PKCS7"):
        if len(key_text) != 16:
            raise ValueError("Key length must be 16")

        self.key_schedule = self.generate_key_schedule(key_text)
        self.mode = mode
        self.padding = padding

        if mode != "ECB":
            if len(iv_text) != 16:
                raise ValueError("IV length must be 16")
            self.iv = iv_text.encode()

    @staticmethod
    def xtime(b):
        if b & 0x80:
            return ((b << 1) ^ 0x1b) & 0xff
        else:
            return (b << 1) & 0xff

    @staticmethod
    def rotate_left(word):
        return word[1:] + word[:1]

    @staticmethod
    def sub_word(word):
        return [AESCipher.sbox_tablecheck(b) for b in word]

    @staticmethod
    def rot_word(word):
        return word[1:] + word[:1]

    @staticmethod
    # AES S-Box
    def sbox_tablecheck(b):
        # 2S-Box
        S = [
            [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
            [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
            [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
            [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
            [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
            [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
            [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
            [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
            [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
            [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
            [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
            [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
            [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
            [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
            [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
            [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
        ]

        return S[int(b >> 4)][int(b & 0x0f)]

    @staticmethod
    def sbox(b):
        # Compute the S-Box value for a given byte
        return GF8(AESCipher.sbox_tablecheck(b))

    @staticmethod
    def sub_bytes(state):
        # Apply the SubBytes transformation to the state matrix
        for i in range(4):
            for j in range(4):
                state[i][j] = AESCipher.sbox(state[i][j])
        return state

    @staticmethod
    def add_round_key(state, key):
        # Apply the AddRoundKey transformation to the state matrix using the given round key
        for i in range(4):
            for j in range(4):
                state[i][j] = state[i][j] ^ key[j][i]
        return state

    def generate_key_schedule(self, key_text):
        RC = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
        # RC = generate_rc()
        w = []

        key_matrix = [ord(c) for c in key_text]
        for i in range(self.Nk):
            # w.append([[GF8(key_matrix[i + 4 * j])] for j in range(4)])
            temp = []
            for j in range(4):
                temp.append(GF8(key_matrix[i * 4 + j]))
            w.append(temp)
        for i in range(self.Nk, self.Nb * (self.Nr + 1)):
            temp = w[i - 1]
            if i % self.Nk == 0:
                temp = AESCipher.sub_word(AESCipher.rot_word(temp))
                temp[0] = temp[0] ^ RC[i // self.Nk - 1]
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = AESCipher.sub_word(temp)
            w.append([w[i - self.Nk][j] ^ temp[j] for j in range(4)])
        return w

    @staticmethod
    def shift_rows(state):
        # Perform the ShiftRows transformation on the state matrix
        for i in range(1, 4):
            state[i] = state[i][i:] + state[i][:i]
        return state

    @staticmethod
    def mix_columns(state):
        # Perform the MixColumns transformation on the state matrix
        for c in range(AESCipher.Nb):
            s = [state[r][c] for r in range(4)]
            state[0][c] = s[0] * GF8(0x02) + s[1] * GF8(0x03) + s[2] * GF8(0x01) + s[3] * GF8(0x01)
            state[1][c] = s[0] * GF8(0x01) + s[1] * GF8(0x02) + s[2] * GF8(0x03) + s[3] * GF8(0x01)
            state[2][c] = s[0] * GF8(0x01) + s[1] * GF8(0x01) + s[2] * GF8(0x02) + s[3] * GF8(0x03)
            state[3][c] = s[0] * GF8(0x03) + s[1] * GF8(0x01) + s[2] * GF8(0x01) + s[3] * GF8(0x02)
        return state

    @staticmethod
    def pkcs7_pad(data, block_size):
        padding_len = block_size - (len(data) % block_size)
        padding = bytes([padding_len] * padding_len)
        return data + padding

    @staticmethod
    def pkcs7_unpad(data):
        padding_len = data[-1]
        return data[:-padding_len]

    def encrypt(self, plain_text):
        if self.mode == "ECB" or self.mode == "CBC" or self.mode == "CTR":
            plain_bytes = self.pkcs7_pad(plain_text.encode(), 16)
        else:
            plain_bytes = plain_text.encode()

        switcher = {
            "ECB": self._encrypt_ecb,
            "CBC": self._encrypt_cbc,
            "OFB": self._encrypt_ofb,
            "CFB": self._encrypt_cfb,
            "CTR": self._encrypt_ctr,
        }
        encrypt_func = switcher.get(self.mode)
        if encrypt_func:
            cipher_bytes = encrypt_func(plain_bytes)
        else:
            raise ValueError("Invalid mode: " + self.mode)

        return cipher_bytes

    def decrypt(self, cipher_hex):
        cipher_bytes = bytes.fromhex(cipher_hex)

        switcher = {
            "ECB": self._decrypt_ecb,
            "CBC": self._decrypt_cbc,
            "OFB": self._decrypt_ofb,
            "CFB": self._decrypt_cfb,
            "CTR": self._decrypt_ctr,
        }
        decrypt_func = switcher.get(self.mode)
        if decrypt_func:
            plain_bytes = decrypt_func(cipher_bytes)
        else:
            raise ValueError("Invalid mode: " + self.mode)

        if self.mode == "ECB" or self.mode == "CBC" or self.mode == "CTR":
            plain_bytes = self.pkcs7_unpad(plain_bytes)

        return plain_bytes.decode()

    def _encrypt_ecb(self, plain_bytes):
        # Encrypt the plaintext using AES encryption with the given key
        cipher_bytes = b""
        for i in range(0, len(plain_bytes), 16):
            data_matrix = [plain_bytes[i + j] for j in range(16)]
            output_matrix = self._encrypt_block(data_matrix)
            cipher_bytes += bytes([output_matrix[j] for j in range(16)])
        return cipher_bytes

    def _encrypt_cbc(self, plain_bytes):
        iv = self.iv
        # Encrypt the plaintext using AES encryption with the given key and IV
        cipher_bytes = b""
        for i in range(0, len(plain_bytes), 16):
            data_matrix = [plain_bytes[i + j] for j in range(16)]
            data_matrix = [data_matrix[j] ^ iv[j] for j in range(16)]
            output_matrix = self._encrypt_block(data_matrix)
            iv = bytes([output_matrix[j] for j in range(16)])
            cipher_bytes += iv
        return cipher_bytes

    def _encrypt_ofb(self, plain_bytes):
        iv = self.iv
        cipher_bytes = b""
        for i in range(0, len(plain_bytes), 16):
            output_matrix = self._encrypt_block(iv)
            cipher_bytes += bytes([plain_bytes[i + j] ^ output_matrix[j] for j in range(16)])
            iv = bytes([output_matrix[j] for j in range(16)])
        return cipher_bytes

    def _encrypt_cfb(self, plain_bytes):
        iv = self.iv
        cipher_bytes = b""
        for i in range(0, len(plain_bytes), 16):
            output_matrix = self._encrypt_block(iv)
            cipher_bytes += bytes([plain_bytes[i + j] ^ output_matrix[j] for j in range(16)])
            iv = iv[16:] + bytes([cipher_bytes[i + j] for j in range(16)])
        return cipher_bytes

    def _encrypt_ctr(self, plain_bytes):
        iv = int.from_bytes(self.iv, "big")
        cipher_bytes = b""
        for i in range(0, len(plain_bytes), 16):
            iv_bytes = iv.to_bytes(16, "big")
            output_matrix = self._encrypt_block(iv_bytes)
            cipher_bytes += bytes([plain_bytes[i + j] ^ output_matrix[j] for j in range(16)])
            iv += 1
        return cipher_bytes

    def _decrypt_ecb(self, cipher_bytes):
        # Decrypt the ciphertext using AES decryption with the given key
        plain_bytes = b""
        for i in range(0, len(cipher_bytes), 16):
            data_matrix = [cipher_bytes[i + j] for j in range(16)]
            output_matrix = self._decrypt_block(data_matrix)
            plain_bytes += bytes([output_matrix[j] for j in range(16)])
        return plain_bytes

    def _decrypt_cbc(self, cipher_bytes):
        iv = self.iv
        # Decrypt the ciphertext using AES decryption with the given key and IV
        plain_bytes = b""
        for i in range(0, len(cipher_bytes), 16):
            data_matrix = [cipher_bytes[i + j] for j in range(16)]
            output_matrix = self._decrypt_block(data_matrix)
            plain_bytes += bytes([output_matrix[j] ^ iv[j] for j in range(16)])
            iv = data_matrix
        return plain_bytes

    def _decrypt_ofb(self, cipher_bytes):
        iv = self.iv
        # Decrypt the ciphertext using AES decryption with the given key and IV
        plain_bytes = b""
        for i in range(0, len(cipher_bytes), 16):
            data_matrix = [iv[j] for j in range(16)]
            output_matrix = self._encrypt_block(data_matrix)
            iv = bytes([output_matrix[j] for j in range(16)])
            plain_bytes += bytes([cipher_bytes[i + j] ^ iv[j] for j in range(16)])
        return plain_bytes

    def _decrypt_cfb(self, cipher_bytes):
        iv = self.iv
        # Decrypt the ciphertext using AES decryption with the given key and IV
        plain_bytes = b""
        for i in range(0, len(cipher_bytes), 16):
            data_matrix = [iv[j] for j in range(16)]
            output_matrix = self._encrypt_block(data_matrix)
            iv = bytes([cipher_bytes[i + j] for j in range(16)])
            plain_bytes += bytes([cipher_bytes[i + j] ^ output_matrix[j] for j in range(16)])
        return plain_bytes

    def _decrypt_ctr(self, cipher_bytes):
        return self._encrypt_ctr(cipher_bytes)

    def _encrypt_block(self, data_matrix):
        # Encrypt the plaintext using AES encryption with the given key
        state = [[GF8(0)] * self.Nb for _ in range(4)]

        # Initialize the state matrix with the plaintext
        for i in range(4):
            for j in range(4):
                state[i][j] = GF8(data_matrix[i + 4 * j])

        # Perform the initial AddRoundKey transformation
        state = AESCipher.add_round_key(state, self.key_schedule[0:AESCipher.Nb])

        # Perform 9 rounds of encryption
        for round in range(1, AESCipher.Nr):
            state = AESCipher.sub_bytes(state)
            state = AESCipher.shift_rows(state)
            state = AESCipher.mix_columns(state)
            state = AESCipher.add_round_key(state, self.key_schedule[round * AESCipher.Nb:(round + 1) * AESCipher.Nb])

        # Perform the final round of encryption
        state = AESCipher.sub_bytes(state)
        state = AESCipher.shift_rows(state)
        state = AESCipher.add_round_key(state,
                                        self.key_schedule[
                                        AESCipher.Nr * AESCipher.Nb:(AESCipher.Nr + 1) * AESCipher.Nb])

        output_matrix = []
        # Convert the encrypted state matrix to a list of bytes
        for i in range(4):
            for j in range(4):
                output_matrix.append(state[j][i].key)
        return output_matrix

    @staticmethod
    def inv_sub_bytes(state):
        # 应用逆SubBytes变换到状态矩阵
        for i in range(4):
            for j in range(4):
                state[i][j] = AESCipher.inv_sbox(state[i][j])
        return state

    @staticmethod
    def inv_sbox_tablecheck(b):
        # 逆S-Box查找表
        S = [
            [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
            [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
            [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
            [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
            [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
            [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
            [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
            [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
            [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
            [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
            [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
            [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
            [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
            [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
            [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
            [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
        ]

        return S[int(b >> 4)][int(b & 0x0f)]

    @staticmethod
    def inv_sbox(b):
        # 计算给定字节的逆S-Box值
        return GF8(AESCipher.inv_sbox_tablecheck(b))

    @staticmethod
    def inv_shift_rows(state):
        # 执行逆ShiftRows变换到状态矩阵
        for i in range(1, 4):
            state[i] = state[i][-i:] + state[i][:-i]
        return state

    @staticmethod
    def inv_mix_columns(state):
        # 执行逆MixColumns变换到状态矩阵
        for c in range(AESCipher.Nb):
            s = [state[r][c] for r in range(4)]
            state[0][c] = s[0] * GF8(0x0e) + s[1] * GF8(0x0b) + s[2] * GF8(0x0d) + s[3] * GF8(0x09)
            state[1][c] = s[0] * GF8(0x09) + s[1] * GF8(0x0e) + s[2] * GF8(0x0b) + s[3] * GF8(0x0d)
            state[2][c] = s[0] * GF8(0x0d) + s[1] * GF8(0x09) + s[2] * GF8(0x0e) + s[3] * GF8(0x0b)
            state[3][c] = s[0] * GF8(0x0b) + s[1] * GF8(0x0d) + s[2] * GF8(0x09) + s[3] * GF8(0x0e)
        return state

    def _decrypt_block(self, data_matrix):
        state = [[GF8(0)] * self.Nb for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[i][j] = GF8(data_matrix[i + 4 * j])

        state = AESCipher.add_round_key(state,
                                        self.key_schedule[
                                        AESCipher.Nr * AESCipher.Nb:(AESCipher.Nr + 1) * AESCipher.Nb])

        for round in range(AESCipher.Nr - 1, 0, -1):
            state = AESCipher.inv_shift_rows(state)
            state = AESCipher.inv_sub_bytes(state)
            state = AESCipher.add_round_key(state, self.key_schedule[round * AESCipher.Nb:(round + 1) * AESCipher.Nb])
            state = AESCipher.inv_mix_columns(state)

        state = AESCipher.inv_shift_rows(state)
        state = AESCipher.inv_sub_bytes(state)
        state = AESCipher.add_round_key(state, self.key_schedule[0:AESCipher.Nb])

        output_matrix = []
        for i in range(4):
            for j in range(4):
                output_matrix.append(state[j][i].key)
        return output_matrix


if __name__ == '__main__':
    # Example usage:
    key = 'Thats my Kung Fu'
    data = 'Two One Nine Two'
    iv = '1234567880123456'

    # Encrypt the plaintext using AES encryption with the given key
    aes = AESCipher(key, "CBC", iv)
    output_bytes = aes.encrypt(data)
    output_hex = ''.join([hex(num)[2:].zfill(2) for num in output_bytes])
    output_text = aes.decrypt(output_hex)
    print(output_hex)
    print(output_text)
