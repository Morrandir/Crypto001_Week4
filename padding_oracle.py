__author__ = 'Qubo'

import urllib2

BLOCK_SIZE = 16

CT = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'
TARGET = 'http://crypto-class.appspot.com/po?er='


class PaddingOracle(object):
    __ciphertext = ''
    __plaintext = ''
    __padding = 0
    __block_size = BLOCK_SIZE
    __block_size_hex = BLOCK_SIZE * 2
    __blocks = 0
    __guess_lower_bound = 1
    __guess_upper_bound = 256

    def __init__(self):
        print('PaddingOracle initializing...')

    def getPlaintext(self):
        return self.__plaintext[:(self.__block_size * self.__blocks) - self.__padding]

    def decrypt(self, cipher):
        print('hacking...')
        self.__ciphertext = cipher
        self.__blocks = len(self.__ciphertext) / self.__block_size_hex
        self.__plaintext = bytearray(self.__block_size * (self.__blocks - 1))  # removing IV block

        for i in range(0, self.__blocks - 1):  # blocks - 1: no need to decrypt the first block (IV)
            self.blockGuess(self.__blocks - i)


    def blockGuess(self, iBlocks):

        padding = 0

        for i in range(0, self.__block_size):

            if i < padding:
                continue

            guess_index = self.__block_size * (iBlocks - 1) - 1 - i
            print('decrypting cipher character No. ' + str(guess_index) + ': '),
            guess_index *= 2  # plain text is byte array but cipher text is hex array, the size ratio is 1:2

            query_trail = ''

            for iTrail in range(1, i + 1):
                pt_index = self.__plaintext[guess_index / 2 + iTrail]
                ct_index = self.__ciphertext[guess_index + iTrail * 2:guess_index + iTrail * 2 + 2]
                mask = format(pt_index ^ (i + 1) ^ int(ct_index, 16), '02x')
                query_trail += mask

            for guess in range(self.__guess_lower_bound, self.__guess_upper_bound):
                if 0 == guess % 32:
                    print('\n.'),
                else:
                    print('.'),

                query = self.__ciphertext[:guess_index]

                ct_index = self.__ciphertext[guess_index:guess_index + 2]
                mask = format(guess ^ (i + 1) ^ int(ct_index, 16), '02x')
                query += mask

                query += query_trail
                query += self.__ciphertext[self.__block_size_hex * (iBlocks - 1):self.__block_size_hex * iBlocks]

                if self.query(query):
                    if i != 0 or iBlocks != self.__blocks:
                        print('Found!')
                        self.__plaintext[guess_index / 2] = chr(guess)
                    else:
                        print('Found real padding: ' + str(guess))
                        self.__plaintext[guess_index / 2] = chr(guess)
                        for iPadding in range(guess_index / 2 - 1, guess_index / 2 - guess, -1):
                            print('decrypting cipher character No. ' + str(iPadding) + ': real padding!')
                            self.__plaintext[iPadding] = chr(guess)
                        self.__padding = padding = guess
                        self.__guess_lower_bound = 32
                        self.__guess_upper_bound = 128  # chars between 32~127 are printable in ASCII table.
                    print self.__plaintext
                    break

                if self.__guess_upper_bound == guess:
                    print('NOT found!')
                    print('Check your code, there must be something wrong...')
                    return


    def query(self, q):
        target = TARGET + urllib2.quote(q)
        req = urllib2.Request(target)

        try:
            urllib2.urlopen(req)  # Wait for response
        except urllib2.HTTPError, e:
            if e.code == 404:
                return True  # good padding
            return False  # bad padding


if __name__ == "__main__":
    po = PaddingOracle()
    po.decrypt(CT)
    plaint_text = po.getPlaintext()
    print plaint_text