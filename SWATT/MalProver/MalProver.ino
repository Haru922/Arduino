#define KEY_LEN 10 
#define ADDRESS_LIMIT 0xffff

// Due to the result of Coupon Collector's Problem
#define ITER_CNT 664000 // ITER_CNT > (2 * 32000ln32000)


uint8_t checksum_vector[8];
uint8_t S[256];


static void
verify_memory () {
    uint8_t i;
    char seed[KEY_LEN+1];
    uint8_t key[KEY_LEN+1];

    // Receive the key from the verifier
    String str = Serial.readString();
    str.toCharArray(seed, KEY_LEN+1);
    for (i=0; i<KEY_LEN+1; i++)
        key[i] = String(seed[i]).toInt();
    Serial.print(F("KEY: "));
    Serial.println(seed);

    // RC4 Key-sheduling algorithm
    rc4_KSA(key);

    // Calculate the eight 8-bit checksum values
    get_checksum();

    // Send checksum vector to the verifier
    for (i=0; i<8; i++) {
        Serial.print(checksum_vector[i]);
        Serial.print(' ');
    }
    Serial.println();
}

static void
rc4_KSA (uint8_t *key) {
    uint16_t i,j;
    // RC4 KSA(Key-scheduling algorithm)
    for (i=0; i<256; i++)
        S[i] = i;
    for (i=0,j=0; i<256; i++) {
        j = (j+S[i]+key[i%KEY_LEN])%256;
        swap(&S[i],&S[j]);
    }
}

static void
rc4_PRGA (uint8_t *i,
          uint8_t *j) {
    // RC4 PRGA(Pseudo-random generation algorithm) PART-1
    *i += 1;
    *j = (*j+S[*i])%256;
    swap(&S[*i],&S[*j]);
    // RC4 PRGA PART-2: S[(S[i]+S[j])%256];
}

static void
get_checksum () {
    uint8_t i,j;
    uint8_t k;
    uint32_t cnt;
    uint8_t prev_rc4, cur_rc4;
    uint16_t addr;

    // Discard RC4[0] to RC4[255] for security reasons
    for (i=0,j=0,cnt=0; cnt<256; cnt++)
        rc4_PRGA(&i,&j);

    // Checksum C[0] t0 C[7] are initialized with RC4[256] through RC4[263]
    for (k=0,cnt=0; cnt<8; cnt++) {
        rc4_PRGA(&i,&j);
        checksum_vector[k++] = S[(S[i]+S[j])%256];
    }

    // The initial value of RC4[i-1] is set to RC4[264]
    rc4_PRGA(&i,&j);
    prev_rc4 = S[(S[i]+S[j])%256];

    // k be the current index into the checksum vector
    for (k=0,cnt=0; cnt<ITER_CNT; cnt++) {

        // Get RC4[i]
        rc4_PRGA(&i,&j);
        cur_rc4 = S[(S[i]+S[j])%256];

        // Construct address for memory read
        addr = ((cur_rc4<<8)+checksum_vector[(k+7)%8]);

        // Update checksum byte
        checksum_vector[k] = (checksum_vector[k]+(pgm_read_byte(addr)^checksum_vector[(k+6)%8]+prev_rc4))&0xff;
        checksum_vector[k] = (checksum_vector[k]<<1)|(checksum_vector[k]>>7);

        prev_rc4 = cur_rc4;

        // Update checksum index
        k = (k+1)%8;
    }
}

static void
dump_memory () {
    uint32_t i=0x0000;
    Serial.print(pgm_read_byte(i));
    for (i=0x0001; i<=ADDRESS_LIMIT; i++) {
        if (!(i%10000))
            Serial.println();
        else
            Serial.print(',');
        Serial.print(pgm_read_byte(i));
    }
    Serial.println();
}

static void
swap (uint8_t *b1,
      uint8_t *b2) {
    uint8_t tmp = *b1;
    *b1 = *b2;
    *b2 = tmp;
}

void
setup () {
    Serial.begin(9600);
}

void
loop () {
    if (Serial.available() > 0) {
        String arg = Serial.readString();
        if (arg.equalsIgnoreCase("ping"))
            // Modify original string "PONG" to "MALICIOUS PROVER"
            Serial.println(F("MALICIOUS PROVER"));
        else if (arg.equalsIgnoreCase("verify")) {
            Serial.println(F("VERIFY MEMORY"));
            verify_memory();
        } else if (arg.equalsIgnoreCase("dump")) {
            Serial.println(F("DUMP MEMORY"));
            dump_memory();
        }
    }
}
