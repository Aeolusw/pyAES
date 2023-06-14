from galois_field import GF8
# from mod_compute import modinv

class AES:
    Nk = 4
    Nb = 4
    Nr = 10

    key_matrix = []
    plain_matrix = []
    cipher_matrix = []

    def __init__(self, key_text, plain_text):
        self.key_matrix = [ord(c) for c in key_text]
        self.plain_matrix = [ord(c) for c in plain_text]

    
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
        return [AES.sbox_tablecheck(b) for b in word]

    @staticmethod
    def rot_word(word):
        return word[1:] + word[:1]

    @staticmethod
    # AES S-Box
    def sbox_tablecheck(b):
        # 2S-Box
        S = [
            [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
            [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
            0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
            [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
            0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
            [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
            0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
            [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
            0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
            [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
            [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
            0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
            [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
            0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
            [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
            0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
            [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
            0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
            [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
            0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
            [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
            0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
            [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
            0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
            [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
            0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
            [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
            0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
            [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
            0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
        ]

        return S[int(b >> 4)][int(b & 0x0f)]

    @staticmethod
    def sbox(b):
        # Compute the S-Box value for a given byte
        return GF8(AES.sbox_tablecheck(b))

    @staticmethod
    def sub_bytes(state):
        # Apply the SubBytes transformation to the state matrix
        for i in range(4):
            for j in range(4):
                state[i][j] = AES.sbox(state[i][j])
        return state

    @staticmethod
    def add_round_key(state, key_schedule, round_num):
        # Apply the AddRoundKey transformation to the state matrix using the given round key
        for i in range(4):
            for j in range(4):
                state[i][j] = state[i][j] ^ key_schedule[round_num][i][j]
        return state

    # def generate_rc():
    #     RC = [0x01]
    #     for i in range(1, 10):
    #         RC.append(xtime(RC[i-1]))
    #     return RC

    def generate_key_schedule(self):
        RC = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
        # RC = generate_rc()
        w = []
        for i in range(self.Nk):
            # w.append([[GF8(key_matrix[i + 4 * j])] for j in range(4)])
            temp = []
            for j in range(4):
                temp.append(GF8(self.key_matrix[i * 4 + j]))
            w.append(temp)
        for i in range(self.Nk, self.Nb*(self.Nr+1)):
            temp = w[i-1]    
            if i % self.Nk == 0:
                temp = AES.sub_word(AES.rot_word(temp))
                temp[0] = temp[0] ^ RC[i//self.Nk - 1]
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = AES.sub_word(temp)
            w.append([w[i-self.Nk][j] ^ temp[j] for j in range(4)])
            # WiM1 = w[i-1]
            # WiMNk = w[i-self.Nk]
            # if i % self.Nk == 0:
            #     s = [AES.sbox(x) for x in AES.rotate_left(WiM1)]
            #     step3 = [s[0] ^ RC[i//self.Nk - 1]]
            #     step3.extend(list(s[j] for j in range(1, 4)))
            #     w.append([WiMNk[j] ^ step3[j] for j in range(4)])
            # elif self.Nk > 6 and i % self.Nk == 4:
            #     s = [sbox_tablecheck(x) for x in WiM1]
            #     w.append([WiMNk[j] ^ s[j] for j in range(4)])
            # else:
            #     w.append([WiMNk[j] ^ WiM1[j] for j in range(4)])
        return w

    def shift_rows(state):
        # Perform the ShiftRows transformation on the state matrix
        for i in range(1, 4):
            state[i] = state[i][i:] + state[i][:i]
        return state

    @staticmethod
    def mix_columns(state):
        # Perform the MixColumns transformation on the state matrix
        for c in range(AES.Nb):
            s = [state[r][c] for r in range(4)]
            state[0][c] = s[0] * GF8(0x02) + s[1] * GF8(0x03) + s[2] * GF8(0x01) + s[3] * GF8(0x01)
            state[1][c] = s[0] * GF8(0x01) + s[1] * GF8(0x02) + s[2] * GF8(0x03) + s[3] * GF8(0x01)
            state[2][c] = s[0] * GF8(0x01) + s[1] * GF8(0x01) + s[2] * GF8(0x02) + s[3] * GF8(0x03)
            state[3][c] = s[0] * GF8(0x03) + s[1] * GF8(0x01) + s[2] * GF8(0x01) + s[3] * GF8(0x02)
        return state

    def encrypt(self):
        # Encrypt the plaintext using AES encryption with the given key
        state = [[GF8(0)] * self.Nb for _ in range(4)]

        # Initialize the state matrix with the plaintext
        for i in range(4):
            for j in range(4):
                state[i][j] = GF8(self.plain_matrix[i + 4 * j])

        # Generate the round keys
        round_keys = self.generate_key_schedule()

        # Perform the initial AddRoundKey transformation
        state = AES.add_round_key(state, round_keys, 0)

        # Perform 9 rounds of encryption
        for round_num in range(1, AES.Nr - 1):
            state = AES.sub_bytes(state)
            state = AES.shift_rows(state)
            state = AES.mix_columns(state)
            state = AES.add_round_key(state, round_keys, round_num)

        # Perform the final round of encryption
        state = AES.sub_bytes(state)
        state = AES.shift_rows(state)
        state = AES.add_round_key(state, round_keys, round_num)

        # Convert the encrypted state matrix to a list of bytes
        for i in range(4):
            for j in range(4):
                self.cipher_matrix.append(state[j][i].key)

        return self.cipher_matrix 

if __name__ == '__main__':
    # Example usage:
    # data = 'Attack at dawn !'
    # key = 'Sixteen byte key'
    key_matrix = 'Thats my Kung Fu'
    data = 'Two One Nine Two'

    # Convert ASCII strings to hexadecimal values
    # plaintext = [ord(c) for c in data]
    # key_text = [ord(c) for c in key]
    
    # Encrypt the plaintext using AES encryption with the given key
    aes = AES(key_matrix, data)
    ciphertext = aes.encrypt()

    print("Ciphertext (Hex):")
    print(' '.join([hex(num)[2:].zfill(2) for num in ciphertext]))