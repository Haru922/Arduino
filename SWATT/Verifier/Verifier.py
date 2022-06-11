#!/usr/bin/env python3


import os
import sys
import time
import serial


BAUDRATE = 9600
WRITE_TIMEOUT = 3
DUMP_PARTITION_CNT = 7
PERFORMANCE_MEASURE = 100
PERFORMANCE_RESULT = 'verify_performance_result'

REQUEST = {0:'quit',1:'ping',2:'verify',3:'dump',4:'performance'}

# Due to the result of the Coupon Collector's Problem
ITER_CNT = 664000 # ITER_CNT > (2 * 32000ln32000)

# Verifier knows the expected memory contents
MEMORY_ORIGIN = 'origin' # Prover's original memory contents

# Prover verification time threshold
VERIFY_TIME_THRESHOLD = 5.5


class Verifier():
    def __init__(self, port):
        self.serial = serial.Serial(port=port,baudrate=BAUDRATE,write_timeout=WRITE_TIMEOUT)
        self.S = [0]*256
        self.origin = None

    def verify(self,performance=False):
        # Use current timestamp for generating key(length=10)
        seed = str(int(time.time()))
        print(f"VERIFIER > KEY: {seed}")

        # Send the key to the prover
        self.serial.write(seed.encode('utf8'))
        print(f"PROVER > {self.serial.readline().decode('utf8')}")

        # Prover verification start
        start_time = time.time()

        # Calculate the eight 8-bit checksum values
        checksum = self.get_checksum(seed)
        print('VERIFIER > CHECKSUM: ',checksum)

        # Receive prover's verification result
        ret_checksum = self.serial.readline().decode('utf8').split(' ')

        # Prover verification procedure finished
        elapsed_time = time.time()-start_time

        ret_checksum = [int(checksum) for checksum in ret_checksum[:-1]]
        print('PROVER > CHECKSUM: ',ret_checksum)
        print(f'VERIFIER > ELAPSED TIME {elapsed_time:.3f}')

        # Check eight 8-bit checksum values and prover verification procedure time
        result = 'Verified' if checksum == ret_checksum and elapsed_time < VERIFY_TIME_THRESHOLD else 'Not Verified'
        print(f'\nVERIFIER > {result}.\n')

        if performance:
            with open(PERFORMANCE_RESULT,'a') as f:
                f.write(f'{result},{elapsed_time:.3f}\n');

    def rc4_KSA(self,key):
        key = [int(n) for n in key]
        key_len = len(key)

        # RC4 KSA(Key-scheduling algorithm)
        for i in range(256):
            self.S[i] = i
        j = 0
        for i in range(256):
            j = (j+self.S[i]+key[i%key_len])%256
            self.S[i],self.S[j] = self.S[j],self.S[i]

    def rc4_PRGA(self,i,j):
        # RC4 PRGA(Pseudo-random generation algorithm) PART-1
        i = (i+1)%256
        j = (j+self.S[i])%256
        self.S[i],self.S[j] = self.S[j],self.S[i]
        # RC4 PRGA PART-2: self.S[(self.S[i]+self.S[j])%256]
        return i,j;

    def get_checksum(self,key):
        self.get_origin()
        checksum_vector = []

        # RC4 Key-sheduling algorithm
        self.rc4_KSA(key)

        # Discard RC4[0] to RC4[255] for security reasons
        i, j = 0, 0
        for cnt in range(256):
            i,j = self.rc4_PRGA(i,j)

        # Checksum C[0] to C[7] are initialized with RC4[256] through RC4[263]
        for cnt in range(8):
            i,j = self.rc4_PRGA(i,j)
            checksum_vector.append(self.S[(self.S[i]+self.S[j])%256])

        # The initial value of RC4[i-1] is set to RC4[264]
        i,j = self.rc4_PRGA(i,j)
        prev_rc4 = self.S[(self.S[i]+self.S[j])%256]

        # k be the current index into the checksum vector
        k = 0

        for cnt in range(ITER_CNT):

            # Get RC4[i]
            i,j = self.rc4_PRGA(i,j)
            cur_rc4 = self.S[(self.S[i]+self.S[j])%256]

            # Construct address for memory read
            addr = ((cur_rc4<<8)+checksum_vector[(k-1)%8])&0xffff

            # Update checksum byte
            checksum_vector[k] = (checksum_vector[k]+(self.origin[addr]^checksum_vector[(k-2)%8]+prev_rc4))&0xff
            checksum_vector[k] = ((checksum_vector[k]<<1)|(checksum_vector[k]>>7))&0xff
            
            prev_rc4 = cur_rc4

            # Update checksum index
            k = (k+1)%8

        return checksum_vector

    def dump(self):
        memory_dump = []
        for i in range(DUMP_PARTITION_CNT):
            memory_dump.append(self.serial.readline()[:-2].decode('utf8'))
        with open(MEMORY_ORIGIN,'w') as f:
            f.writelines(','.join(memory_dump))

    def check_origin(self):
        if not os.path.isfile(MEMORY_ORIGIN):
            self.request('dump')

    def get_origin(self):
        with open(MEMORY_ORIGIN,'r') as f:
            self.origin = f.readline().split(',')
        self.origin = [int(content) for content in self.origin]

    def request(self, req):
        if 'performance' == req:
            self.check_origin()
            for i in range(PERFORMANCE_MEASURE):
                self.serial.write('verify'.encode('utf8'))
                print(f"PROVER > {self.serial.readline().decode('utf8')}")
                self.verify(performance=True)
        elif 'verify' == req:
            self.check_origin()
            self.serial.write(req.encode('utf8'))
            print(f"PROVER > {self.serial.readline().decode('utf8')}")
            self.verify()
        else:
            self.serial.write(req.encode('utf8'))
            print(f"PROVER > {self.serial.readline().decode('utf8')}")
            if 'dump' == req:
                self.dump()

    def run(self):
        while True:
            print('0: QUIT   1: PING   2: VERIFY  3: DUMP  4: PERFORMANCE')
            selection = input('IN > ')
            print()
            if selection.isdigit() and int(selection) in REQUEST:
                selection = int(selection)
            else:
                print('VERIFIER > Invalid Selection\n')
                continue
            if 0 == selection:
                print('VERIFIER > Quit\n')
                break
            else:
                print('VERIFIER > SELECTION: ',REQUEST[selection])
                self.request(REQUEST[selection])
                print()


if __name__=='__main__':
    if 1 >= len(sys.argv):
        print('usage: python3 Verifier.py SERIAL_PORT')
    else:
        verifier = Verifier(sys.argv[1])
        verifier.run()
