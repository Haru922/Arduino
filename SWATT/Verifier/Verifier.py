#!/usr/bin/env python3

import os
import sys
import time
import serial
import random

ITER_CNT = 664000
BAUDRATE = 9600
VERIFY_TIMEOUT = 42
WRITE_TIMEOUT = 3
MEMORY_ORIGIN = 'origin'
PERFORMANCE_MEASURE = 100
PERFORMANCE_RESULT = 'verify_performance_result'

REQUEST = {0:'quit',1:'ping',2:'verify',3:'dump',4:'performance'}

class Verifier():
    def __init__(self, port):
        self.serial = serial.Serial(port=port,baudrate=BAUDRATE,write_timeout=WRITE_TIMEOUT)
        self.S = [0]*256
        self.K = [0]*256
        self.origin = None

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

    def dump(self):
        memory_dump = []
        for i in range(7):
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

    def verify(self,performance=False):
        seed = str(int(time.time()))
        print(f"VERIFIER > KEY: {seed}")
        self.serial.write(seed.encode('utf8'))
        print(f"PROVER > {self.serial.readline().decode('utf8')}")
        start_time = time.time()
        checksum = self.get_checksum(seed)
        print('VERIFIER > CHECKSUM: ',checksum)
        ret_checksum = self.serial.readline().decode('utf8').split(' ')
        ret_checksum = [int(checksum) for checksum in ret_checksum[:-1]]
        print('PROVER > CHECKSUM: ',ret_checksum)
        elapsed_time = time.time()-start_time
        print(f'VERIFIER > ELAPSED TIME {elapsed_time:.3f}')
        print('\nVERIFIER > Verified.\n' if checksum == ret_checksum and elapsed_time < VERIFY_TIMEOUT else '\nVERIFIER > Not Verified.\n')
        if performance:
            with open(PERFORMANCE_RESULT,'a') as f:
                f.write(f'{elapsed_time:.3f}\n');

    def shuffle(self,i,j):
        i = (i+1)%256
        j = (j+self.S[i])%256
        self.S[i],self.S[j] = self.S[j],self.S[i]
        return i,j;

    def initialize(self,key):
        key = [int(n) for n in key]
        key_len = len(key)
        for i in range(256):
            self.S[i] = i
            self.K[i] = key[i%key_len]
        j = 0
        for i in range(256):
            j = (j+self.S[i]+self.K[i])%256
            self.S[i],self.S[j] = self.S[j],self.S[i]

    def get_checksum(self,key):
        self.get_origin()
        checksum_vector = []
        self.initialize(key)
        i, j = 0, 0
        for cnt in range(256):
            i,j = self.shuffle(i,j)
        for cnt in range(8):
            i,j = self.shuffle(i,j)
            checksum_vector.append(self.S[(self.S[i]+self.S[j])%256])
        i,j = self.shuffle(i,j)
        prev_rc4 = self.S[(self.S[i]+self.S[j])%256]
        k = 7
        for cnt in range(ITER_CNT):
            i,j = self.shuffle(i,j)
            cur_rc4 = self.S[(self.S[i]+self.S[j])%256]
            addr = ((cur_rc4<<8)+checksum_vector[(k-1)%8])&0xffff
            checksum_vector[k] = (checksum_vector[k]+(self.origin[addr]^checksum_vector[(k-2)%8]+prev_rc4))&0xff
            checksum_vector[k] = ((checksum_vector[k]<<1)|(checksum_vector[k]>>7))&0xff
            prev_rc4 = cur_rc4
            k = (k+1)%8
        return checksum_vector

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
        print('usage: python3 verifier.py SERIAL_PORT')
    else:
        verifier = Verifier(sys.argv[1])
        verifier.run()
