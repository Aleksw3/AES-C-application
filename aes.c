#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROTATE_32_LEFT(value) ((value&0x00FFFFFF) << 8) | ((value&0xFF000000) >> 24)

#define byte_swap_keys(key) ((key&0x000000FF << 24) | (key&0x0000FF00 << 8) | (key&0x00FF0000 >> 8) | (key&0xFF000000 >> 24))

void print_msg_hex(uint32_t* msg, uint16_t msg_length)
{
    printf("Msg       = ");
    for(uint16_t i = 0; i < msg_length/4; i++){
        if(i % 4 == 0 && i > 0) printf(" ");
        printf("%08lx", msg[i]);
    }
    printf("\n");    
    
}
void print_cipher(uint32_t* cipher, uint32_t msg_length)
{
    const uint8_t number_of_blocks = msg_length >= 128 ? msg_length/128 : 1;
    for(uint8_t block = 0; block < number_of_blocks; block++)
    {
        printf("Encrypted Block %02i: ", block);
        for(uint8_t word = 0; word < 4; word++)
            printf("%08lx ", cipher[block*4 + word]);
        printf("\n");    
    }   
}
void print_roundkeys(uint32_t* key, uint16_t key_length)
{
    const uint8_t number_of_keys = (key_length == 128) ? 11 : (key_length == 192) ? 13 : 15;
    for(uint8_t round = 0; round < number_of_keys; round++)
    {
        printf("RoundKey %02i: ", round);
        for(uint8_t word = 0; word < 4; word++)
            printf("%08lx ", key[round*4 + word]);
        printf("\n");    
    }    
}

void key_scheduler(const uint32_t* key, const uint16_t key_length, uint32_t* round_keys)
{
    uint8_t rounds = (key_length == 128) ? 10 : (key_length == 192) ? 12 : 14;
    uint8_t nr_key_words = key_length/32;
    uint8_t rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

    for(uint8_t i = 0; i <  4 * rounds + 4; i++)
    {
        if(i < nr_key_words)
            round_keys[i] = key[i];
        else if(i >= nr_key_words && i % nr_key_words == 0)
        {
            round_keys[i] = 0;
            uint32_t tmp_key_i = ROTATE_32_LEFT(round_keys[i - 1]);
            asm volatile("aes32esi %0, %1, %2, 0":"=r"(round_keys[i]): "0"(round_keys[i]), "r"(tmp_key_i));
            asm volatile("aes32esi %0, %1, %2, 1":"=r"(round_keys[i]): "0"(round_keys[i]), "r"(tmp_key_i));
            asm volatile("aes32esi %0, %1, %2, 2":"=r"(round_keys[i]): "0"(round_keys[i]), "r"(tmp_key_i));
            asm volatile("aes32esi %0, %1, %2, 3":"=r"(round_keys[i]): "0"(round_keys[i]), "r"(tmp_key_i));

            round_keys[i] = round_keys[i] ^ (rcon[i/nr_key_words - 1] << 24);
            round_keys[i] = round_keys[i] ^ round_keys[i - nr_key_words];
        }
        else if(i >= nr_key_words && 
                nr_key_words > 6  && 
                i % nr_key_words == 4)
        {
            round_keys[i] = 0;
            asm volatile("aes32esi %0, %1, %2, 0":"=r"(round_keys[i]): "0"(round_keys[i]),"r"(round_keys[i - 1]));
            asm volatile("aes32esi %0, %1, %2, 1":"=r"(round_keys[i]): "0"(round_keys[i]),"r"(round_keys[i - 1]));
            asm volatile("aes32esi %0, %1, %2, 2":"=r"(round_keys[i]): "0"(round_keys[i]),"r"(round_keys[i - 1]));
            asm volatile("aes32esi %0, %1, %2, 3":"=r"(round_keys[i]): "0"(round_keys[i]),"r"(round_keys[i - 1]));
            round_keys[i] = round_keys[i] ^ round_keys[i - nr_key_words];
        }
        else 
        {
            round_keys[i] = round_keys[i - 1] ^ round_keys[i - nr_key_words];
        }
    }
}

// Create keys for decryption when using the equivalent decryption approach (see FIPS definition 5.3.5)
void InvMixColKey(uint32_t* keys, const uint16_t key_length, uint32_t* new_keys)
{
    uint8_t rounds = (key_length == 128) ? 10 : (key_length == 192) ? 12 : 14;
    uint8_t number_of_words = (rounds+1)*4;

    for(uint8_t i = 0; i < number_of_words; i++)
    {
        if(i < 4 || i >= number_of_words - 4)
            new_keys[i] = keys[i];
        else {
            uint32_t tmp = 0;
            asm volatile("aes32esi  %0, %1, %2, 0": "=r"(tmp)  : "0"(tmp), "r"(keys[i]));
            asm volatile("aes32esi  %0, %1, %2, 1": "=r"(tmp)  : "0"(tmp), "r"(keys[i]));
            asm volatile("aes32esi  %0, %1, %2, 2": "=r"(tmp)  : "0"(tmp), "r"(keys[i]));
            asm volatile("aes32esi  %0, %1, %2, 3": "=r"(tmp)  : "0"(tmp), "r"(keys[i]));

            uint32_t tmp2 = 0;
            asm volatile("aes32dsmi %0, %1, %2, 0": "=r"(tmp2)  : "0"(tmp2), "r"(tmp));
            asm volatile("aes32dsmi %0, %1, %2, 1": "=r"(tmp2)  : "0"(tmp2), "r"(tmp));
            asm volatile("aes32dsmi %0, %1, %2, 2": "=r"(tmp2)  : "0"(tmp2), "r"(tmp));
            asm volatile("aes32dsmi %0, %1, %2, 3": "=r"(tmp2)  : "0"(tmp2), "r"(tmp));
            new_keys[i] = tmp2;
        }
    }
}

void encrypt(uint32_t* msg, uint16_t msg_length, uint32_t* round_keys, uint16_t key_length, uint32_t* cipher, uint16_t cipher_length)
{
    const uint8_t rounds = (key_length == 128) ? 10 : (key_length == 192) ? 12 : 14;

    uint32_t* padded_msg = malloc(cipher_length);

    memset(padded_msg, 0, cipher_length); 
    memcpy(padded_msg, msg, msg_length);
    
    for(uint8_t msg_block = 0; msg_block < cipher_length/128; msg_block++)
    {
        cipher[msg_block*4 + 0] = padded_msg[msg_block*4 + 0] ^ round_keys[0]; 
        cipher[msg_block*4 + 1] = padded_msg[msg_block*4 + 1] ^ round_keys[1];
        cipher[msg_block*4 + 2] = padded_msg[msg_block*4 + 2] ^ round_keys[2];
        cipher[msg_block*4 + 3] = padded_msg[msg_block*4 + 3] ^ round_keys[3];

        // 10/12/14 rounds with MixColumn
        for(uint8_t i = 1; i < rounds; i++){
            uint32_t key_tmp[4]    = {round_keys[i*4+0], round_keys[i*4+1], round_keys[i*4+2], round_keys[i*4+3]};
            uint32_t cipher_tmp[4] = {cipher[msg_block*4 + 0], cipher[msg_block*4 + 1], cipher[msg_block*4 + 2], cipher[msg_block*4 + 3]};
           
            asm volatile("aes32esmi %0, %1, %2, 0": "=r"(key_tmp[0])             : "0"(key_tmp[0]), "r"(cipher_tmp[0]));
            asm volatile("aes32esmi %0, %1, %2, 1": "=r"(key_tmp[0])             : "0"(key_tmp[0]), "r"(cipher_tmp[1]));
            asm volatile("aes32esmi %0, %1, %2, 2": "=r"(key_tmp[0])             : "0"(key_tmp[0]), "r"(cipher_tmp[2]));
            asm volatile("aes32esmi %0, %1, %2, 3": "=r"(cipher[msg_block*4 + 0]): "0"(key_tmp[0]), "r"(cipher_tmp[3]));

            asm volatile("aes32esmi %0, %1, %2, 0": "=r"(key_tmp[1])             : "0"(key_tmp[1]), "r"(cipher_tmp[1]));
            asm volatile("aes32esmi %0, %1, %2, 1": "=r"(key_tmp[1])             : "0"(key_tmp[1]), "r"(cipher_tmp[2]));
            asm volatile("aes32esmi %0, %1, %2, 2": "=r"(key_tmp[1])             : "0"(key_tmp[1]), "r"(cipher_tmp[3]));
            asm volatile("aes32esmi %0, %1, %2, 3": "=r"(cipher[msg_block*4 + 1]): "0"(key_tmp[1]), "r"(cipher_tmp[0]));

            asm volatile("aes32esmi %0, %1, %2, 0": "=r"(key_tmp[2])             : "0"(key_tmp[2]), "r"(cipher_tmp[2]));
            asm volatile("aes32esmi %0, %1, %2, 1": "=r"(key_tmp[2])             : "0"(key_tmp[2]), "r"(cipher_tmp[3]));
            asm volatile("aes32esmi %0, %1, %2, 2": "=r"(key_tmp[2])             : "0"(key_tmp[2]), "r"(cipher_tmp[0]));
            asm volatile("aes32esmi %0, %1, %2, 3": "=r"(cipher[msg_block*4 + 2]): "0"(key_tmp[2]), "r"(cipher_tmp[1]));

            asm volatile("aes32esmi %0, %1, %2, 0": "=r"(key_tmp[3])             : "0"(key_tmp[3]), "r"(cipher_tmp[3]));
            asm volatile("aes32esmi %0, %1, %2, 1": "=r"(key_tmp[3])             : "0"(key_tmp[3]), "r"(cipher_tmp[0]));
            asm volatile("aes32esmi %0, %1, %2, 2": "=r"(key_tmp[3])             : "0"(key_tmp[3]), "r"(cipher_tmp[1]));
            asm volatile("aes32esmi %0, %1, %2, 3": "=r"(cipher[msg_block*4 + 3]): "0"(key_tmp[3]), "r"(cipher_tmp[2]));
        }
        uint32_t key_tmp[4]    = {round_keys[rounds*4 +0], round_keys[rounds*4 +1], round_keys[rounds*4 +2], round_keys[rounds*4 +3]};
        uint32_t cipher_tmp[4] = {cipher[msg_block*4 + 0], cipher[msg_block*4 + 1], cipher[msg_block*4 + 2], cipher[msg_block*4 + 3]};

        asm volatile("aes32esi %0, %1, %2, 0": "=r"(key_tmp[0]             ): "0"(key_tmp[0]), "r"(cipher_tmp[0]));
        asm volatile("aes32esi %0, %1, %2, 1": "=r"(key_tmp[0]             ): "0"(key_tmp[0]), "r"(cipher_tmp[1]));
        asm volatile("aes32esi %0, %1, %2, 2": "=r"(key_tmp[0]             ): "0"(key_tmp[0]), "r"(cipher_tmp[2]));
        asm volatile("aes32esi %0, %1, %2, 3": "=r"(cipher[msg_block*4 + 0]): "0"(key_tmp[0]), "r"(cipher_tmp[3]));

        asm volatile("aes32esi %0, %1, %2, 0": "=r"(key_tmp[1]             ): "0"(key_tmp[1]), "r"(cipher_tmp[1]));
        asm volatile("aes32esi %0, %1, %2, 1": "=r"(key_tmp[1]             ): "0"(key_tmp[1]), "r"(cipher_tmp[2]));
        asm volatile("aes32esi %0, %1, %2, 2": "=r"(key_tmp[1]             ): "0"(key_tmp[1]), "r"(cipher_tmp[3]));
        asm volatile("aes32esi %0, %1, %2, 3": "=r"(cipher[msg_block*4 + 1]): "0"(key_tmp[1]), "r"(cipher_tmp[0]));

        asm volatile("aes32esi %0, %1, %2, 0": "=r"(key_tmp[2]             ): "0"(key_tmp[2]), "r"(cipher_tmp[2]));
        asm volatile("aes32esi %0, %1, %2, 1": "=r"(key_tmp[2]             ): "0"(key_tmp[2]), "r"(cipher_tmp[3]));
        asm volatile("aes32esi %0, %1, %2, 2": "=r"(key_tmp[2]             ): "0"(key_tmp[2]), "r"(cipher_tmp[0]));
        asm volatile("aes32esi %0, %1, %2, 3": "=r"(cipher[msg_block*4 + 2]): "0"(key_tmp[2]), "r"(cipher_tmp[1]));

        asm volatile("aes32esi %0, %1, %2, 0": "=r"(key_tmp[3]             ): "0"(key_tmp[3]), "r"(cipher_tmp[3]));
        asm volatile("aes32esi %0, %1, %2, 1": "=r"(key_tmp[3]             ): "0"(key_tmp[3]), "r"(cipher_tmp[0]));
        asm volatile("aes32esi %0, %1, %2, 2": "=r"(key_tmp[3]             ): "0"(key_tmp[3]), "r"(cipher_tmp[1]));
        asm volatile("aes32esi %0, %1, %2, 3": "=r"(cipher[msg_block*4 + 3]): "0"(key_tmp[3]), "r"(cipher_tmp[2]));
    }
    free(padded_msg);
}

void decrypt(uint32_t* cipher, uint16_t cipher_length, uint32_t* round_keys, uint16_t key_length, uint32_t* cleartext)
{
    uint8_t rounds = (key_length == 128) ? 10 : (key_length == 192) ? 12 : 14;
    uint8_t input_blocks = cipher_length/128;

    for(uint8_t msg_block = 0; msg_block < input_blocks; msg_block++)
    {
        cleartext[msg_block*4 + 0] = cipher[msg_block*4 + 0] ^ round_keys[rounds*4+0]; 
        cleartext[msg_block*4 + 1] = cipher[msg_block*4 + 1] ^ round_keys[rounds*4+1];
        cleartext[msg_block*4 + 2] = cipher[msg_block*4 + 2] ^ round_keys[rounds*4+2];
        cleartext[msg_block*4 + 3] = cipher[msg_block*4 + 3] ^ round_keys[rounds*4+3];

        // 10/12/14 rounds with MixColumn
        for(uint8_t i = rounds-1; i > 0 ; i--){
            uint32_t key_tmp[4] = {round_keys[i*4+0], round_keys[i*4+1], round_keys[i*4+2],round_keys[i*4+3]};
            uint32_t cleartext_tmp[4] = {cleartext[0], cleartext[1], cleartext[2], cleartext[3]};

            asm volatile("aes32dsmi %0, %1, %2, 0": "=r"(key_tmp[0])   : "0"(key_tmp[0]), "r"(cleartext_tmp[0]));
            asm volatile("aes32dsmi %0, %1, %2, 1": "=r"(key_tmp[0])   : "0"(key_tmp[0]), "r"(cleartext_tmp[3]));
            asm volatile("aes32dsmi %0, %1, %2, 2": "=r"(key_tmp[0])   : "0"(key_tmp[0]), "r"(cleartext_tmp[2]));
            asm volatile("aes32dsmi %0, %1, %2, 3": "=r"(cleartext[0] ): "0"(key_tmp[0]), "r"(cleartext_tmp[1]));

            asm volatile("aes32dsmi %0, %1, %2, 0": "=r"(key_tmp[1])   : "0"(key_tmp[1]), "r"(cleartext_tmp[1]));
            asm volatile("aes32dsmi %0, %1, %2, 1": "=r"(key_tmp[1])   : "0"(key_tmp[1]), "r"(cleartext_tmp[0]));
            asm volatile("aes32dsmi %0, %1, %2, 2": "=r"(key_tmp[1])   : "0"(key_tmp[1]), "r"(cleartext_tmp[3]));
            asm volatile("aes32dsmi %0, %1, %2, 3": "=r"(cleartext[1] ): "0"(key_tmp[1]), "r"(cleartext_tmp[2]));

            asm volatile("aes32dsmi %0, %1, %2, 0": "=r"(key_tmp[2])   : "0"(key_tmp[2]), "r"(cleartext_tmp[2]));
            asm volatile("aes32dsmi %0, %1, %2, 1": "=r"(key_tmp[2])   : "0"(key_tmp[2]), "r"(cleartext_tmp[1]));
            asm volatile("aes32dsmi %0, %1, %2, 2": "=r"(key_tmp[2])   : "0"(key_tmp[2]), "r"(cleartext_tmp[0]));
            asm volatile("aes32dsmi %0, %1, %2, 3": "=r"(cleartext[2] ): "0"(key_tmp[2]), "r"(cleartext_tmp[3]));

            asm volatile("aes32dsmi %0, %1, %2, 0": "=r"(key_tmp[3])   : "0"(key_tmp[3]), "r"(cleartext_tmp[3]));
            asm volatile("aes32dsmi %0, %1, %2, 1": "=r"(key_tmp[3])   : "0"(key_tmp[3]), "r"(cleartext_tmp[2]));
            asm volatile("aes32dsmi %0, %1, %2, 2": "=r"(key_tmp[3])   : "0"(key_tmp[3]), "r"(cleartext_tmp[1]));
            asm volatile("aes32dsmi %0, %1, %2, 3": "=r"(cleartext[3] ): "0"(key_tmp[3]), "r"(cleartext_tmp[0]));
        }
        uint32_t key_tmp[4]    = {round_keys[0], round_keys[1], round_keys[2], round_keys[3]};
        uint32_t cleartext_tmp[4] = {cleartext[0], cleartext[1], cleartext[2], cleartext[3]};
        
        asm volatile("aes32dsi %0, %1, %2, 0": "=r"(key_tmp[0]   )   : "0"(key_tmp[0]), "r"(cleartext_tmp[0]));
        asm volatile("aes32dsi %0, %1, %2, 1": "=r"(key_tmp[0]   )   : "0"(key_tmp[0]), "r"(cleartext_tmp[3]));
        asm volatile("aes32dsi %0, %1, %2, 2": "=r"(key_tmp[0]   )   : "0"(key_tmp[0]), "r"(cleartext_tmp[2]));
        asm volatile("aes32dsi %0, %1, %2, 3": "=r"(cleartext[0] )   : "0"(key_tmp[0]), "r"(cleartext_tmp[1]));

        asm volatile("aes32dsi %0, %1, %2, 0": "=r"(key_tmp[1]   )   : "0"(key_tmp[1]), "r"(cleartext_tmp[1]));
        asm volatile("aes32dsi %0, %1, %2, 1": "=r"(key_tmp[1]   )   : "0"(key_tmp[1]), "r"(cleartext_tmp[0]));
        asm volatile("aes32dsi %0, %1, %2, 2": "=r"(key_tmp[1]   )   : "0"(key_tmp[1]), "r"(cleartext_tmp[3]));
        asm volatile("aes32dsi %0, %1, %2, 3": "=r"(cleartext[1] )   : "0"(key_tmp[1]), "r"(cleartext_tmp[2]));

        asm volatile("aes32dsi %0, %1, %2, 0": "=r"(key_tmp[2]   )   : "0"(key_tmp[2]), "r"(cleartext_tmp[2]));
        asm volatile("aes32dsi %0, %1, %2, 1": "=r"(key_tmp[2]   )   : "0"(key_tmp[2]), "r"(cleartext_tmp[1]));
        asm volatile("aes32dsi %0, %1, %2, 2": "=r"(key_tmp[2]   )   : "0"(key_tmp[2]), "r"(cleartext_tmp[0]));
        asm volatile("aes32dsi %0, %1, %2, 3": "=r"(cleartext[2] )   : "0"(key_tmp[2]), "r"(cleartext_tmp[3]));

        asm volatile("aes32dsi %0, %1, %2, 0": "=r"(key_tmp[3]   )   : "0"(key_tmp[3]), "r"(cleartext_tmp[3]));
        asm volatile("aes32dsi %0, %1, %2, 1": "=r"(key_tmp[3]   )   : "0"(key_tmp[3]), "r"(cleartext_tmp[2]));
        asm volatile("aes32dsi %0, %1, %2, 2": "=r"(key_tmp[3]   )   : "0"(key_tmp[3]), "r"(cleartext_tmp[1]));
        asm volatile("aes32dsi %0, %1, %2, 3": "=r"(cleartext[3] )   : "0"(key_tmp[3]), "r"(cleartext_tmp[0]));
    }
}


int main(int argc, char *argv[])
{
    // AES Inputs
    uint16_t key_length = 128;
    uint32_t aes_key[4] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f};
    uint32_t msg[4]     = {0x00112233, 0x44556677,0x8899aabb, 0xccddeeff};

    uint16_t msg_length = sizeof(msg)/sizeof(char);

    // KeyScheduler to produce RoundKeys
    uint8_t rounds = (key_length == 128) ? 10 : (key_length == 192) ? 12 : 14;
    uint8_t nr_round_keys = 4 * (rounds + 1);
    uint32_t* enc_round_keys = malloc(nr_round_keys * sizeof(uint32_t));
    
    key_scheduler(aes_key, key_length, enc_round_keys);
    
    // Encryption
    uint16_t cipher_length = msg_length/128 * 128 + 128;
    uint32_t* cipher = malloc(cipher_length);    

    encrypt(msg, msg_length, enc_round_keys, key_length, cipher, cipher_length);
    printf("Encrypted message\r\n");
    print_cipher(cipher, msg_length);

    // Decryption
    printf("\n\n DECRYPTION \n");
    uint32_t* dec_round_keys = malloc(nr_round_keys*sizeof(uint32_t));
    InvMixColKey(enc_round_keys, key_length, dec_round_keys);

    uint32_t* decipher = malloc(cipher_length);
    
    decrypt(cipher, cipher_length, dec_round_keys, key_length, decipher); 
    
    printf("Decrypted message\r\n");
    print_msg_hex(decipher, msg_length);
}