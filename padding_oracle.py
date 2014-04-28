__author__ = 'Qubo'

import urllib2

BLOCK_SIZE = 16

CT = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'
TARGET = 'http://crypto-class.appspot.com/po?er='


class PaddingOracle(object):
    __ciphertext = ''
    __plaintext = ''
    # __len_CT = 0
    # __len_PT = 0
    __padding = 0
    __block_size = BLOCK_SIZE
    __block_size_hex = BLOCK_SIZE * 2
    __blocks = 0

    def __init__(self):
        print('PaddingOracle initializing...')


    def hack(self, cipher):
        print('hacking...')
        self.__ciphertext = cipher
        # self.__len_CT = len(cipher)
        self.__blocks = len(self.__ciphertext) / self.__block_size_hex
        self.__plaintext = bytearray(len(self.__ciphertext) / 2 - self.__block_size)  # removing IV block
        self.realPadding()

        for i in range(self.__padding + 1, len(self.__plaintext)):
            guess_index = (len(self.__plaintext) - i) * 2  # note that IV needs to be considered
            print('decrypting cipher character No. ' + str(guess_index / 2)),

            query_trail = ''

            for trail in range(1, i):
                pt_index = self.__plaintext[guess_index / 2 + trail]
                ct_index = self.__ciphertext[guess_index + trail * 2:guess_index + trail * 2 + 2]
                mask = format(pt_index ^ i ^ int(ct_index, 16), '02x')
                query_trail += mask

            for guess in range(32, 127):
                print('.'),

                query = self.__ciphertext[:guess_index]

                ct_index = self.__ciphertext[guess_index:guess_index + 2]
                mask = format(guess ^ i ^ int(ct_index, 16), '02x')
                query += mask

                query += query_trail
                query += self.__ciphertext[guess_index + i * 2:]

                if self.query(query):
                    print('Found!')
                    self.__plaintext[guess_index / 2] = chr(guess)
                    print self.__plaintext


    def query(self, q):
        target = TARGET + urllib2.quote(q)
        req = urllib2.Request(target)

        try:
            urllib2.urlopen(req)  # Wait for response
        except urllib2.HTTPError, e:
            if e.code == 404:
                return True  # good padding
            return False  # bad padding


    #--------------------------------------------------------------------------
    # here we decide the real padding size in order to discard them
    #--------------------------------------------------------------------------
    def realPadding(self):
        print('determining the real padding'),

        guess_index = self.__block_size_hex * (
            self.__blocks - 1) - 1  # we use the last char on the (n - 1)th block to help us guess the real padding

        for guess in range(1, 17):
            ct_index = self.__ciphertext[guess_index]
            padding = format(guess ^ 1 ^ int(ct_index), '01x')
            query = self.__ciphertext[:guess_index] + padding + self.__ciphertext[guess_index + 1:]
            print('.'),
            if self.query(query):
                print('\nDone! Real padding is ' + str(guess))
                self.__padding = guess
                break
                # else:
                #     print('no good...')

        for i in range(len(self.__plaintext) - self.__padding, len(self.__plaintext)):
            self.__plaintext[i] = chr(self.__padding)


if __name__ == "__main__":
    po = PaddingOracle()
    po.hack(CT)





