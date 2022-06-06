#define KEY_LEN 10 
#define ITER_CNT 664000
#define ADDRESS_LIMIT 0xffff

uint8_t checksum_vector[8];
uint8_t S[256];
uint8_t K[256];

void setup() {
    Serial.begin(9600);
}

void swap(uint8_t *b1, uint8_t *b2) {
    uint8_t tmp = *b1;
    *b1 = *b2;
    *b2 = tmp;
}

void dump_memory() {
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

void shuffle(uint8_t *i, uint8_t *j) {
    *i += 1;
    *j = (*j+S[*i])%256;
    swap(&S[*i],&S[*j]);
}

void initialize(uint8_t *key) {
    uint16_t i,j;
    for (i=0; i<256; i++) {
        S[i] = i;
        K[i] = key[i%KEY_LEN];
    }
    for (i=0,j=0; i<256; i++) {
        j = (j+S[i]+K[i])%256;
        swap(&S[i],&S[j]);
    }
}

void get_checksum() {
    uint8_t i,j;
    uint8_t k;
    uint32_t cnt;
    uint8_t prev_rc4, cur_rc4;
    uint16_t addr;
    for (i=0,j=0,cnt=0; cnt<256; cnt++)
        shuffle(&i,&j);
    for (k=0,cnt=0; cnt<8; cnt++) {
        shuffle(&i,&j);
        checksum_vector[k++] = S[(S[i]+S[j])%256];
    }
    shuffle(&i,&j);
    prev_rc4 = S[(S[i]+S[j])%256];
    for (k=7,cnt=0; cnt<ITER_CNT; cnt++) {
        shuffle(&i,&j);
        cur_rc4 = S[(S[i]+S[j])%256];
        addr = ((cur_rc4<<8)+checksum_vector[(k+7)%8]);
        checksum_vector[k] = (checksum_vector[k]+(pgm_read_byte(addr)^checksum_vector[(k+6)%8]+prev_rc4))&0xff;
        checksum_vector[k] = (checksum_vector[k]<<1)|(checksum_vector[k]>>7);
        prev_rc4 = cur_rc4;
        k = (k+1)%8;
    }
}

void verify_memory() {
    uint8_t i;
    char seed[KEY_LEN+1];
    uint8_t key[KEY_LEN+1];
    String str = Serial.readString();
    str.toCharArray(seed, KEY_LEN+1);
    for (i=0; i<KEY_LEN+1; i++)
        key[i] = String(seed[i]).toInt();
    Serial.print(F("KEY: "));
    Serial.println(seed);
    initialize(key);
    get_checksum();
    for (i=0; i<8; i++) {
        Serial.print(checksum_vector[i]);
        Serial.print(' ');
    }
    Serial.println();
}

void loop() {
    if (Serial.available() > 0) {
        String arg = Serial.readString();
        if (arg.equalsIgnoreCase("ping"))
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
