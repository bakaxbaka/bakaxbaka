/**
 * Bitcoin Puzzle ECDSA Solver
 * Brute-force search for private keys on secp256k1 curve
 * Optimized for bits 64-75 (feasible range)
 * 
 * Compilation: gcc -O3 -o bitcoin_solver bitcoin_solver.c -lcrypto -lm
 * Usage: ./bitcoin_solver <target_bit> [num_threads]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <time.h>
#include <pthread.h>

#define SECP256K1_N "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
#define MAX_THREADS 16

typedef struct {
    int bit_num;
    unsigned long start_key;
    unsigned long end_key;
    const char *target_hash160;
    int thread_id;
    int found;
    unsigned long solution_key;
} thread_args_t;

/** Compute SHA256 hash */
void sha256(const unsigned char *data, size_t len, unsigned char *hash) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(hash, &ctx);
}

/** Compute RIPEMD160(SHA256(data)) - Bitcoin hash160 */
void hash160(const unsigned char *data, size_t len, unsigned char *hash) {
    unsigned char sha[SHA256_DIGEST_LENGTH];
    RIPEMD160_CTX ctx;
    
    sha256(data, len, sha);
    
    RIPEMD160_Init(&ctx);
    RIPEMD160_Update(&ctx, sha, SHA256_DIGEST_LENGTH);
    RIPEMD160_Final(hash, &ctx);
}

/** Convert hex string to bytes */
void hex_to_bytes(const char *hex, unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(&hex[i*2], "%2hhx", &bytes[i]);
    }
}

/** Convert bytes to hex string */
void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(&hex[i*2], "%02x", bytes[i]);
    }
}

/** Get public key hash160 from private key */
int get_hash160(unsigned long privkey, unsigned char *hash160_out) {
    EC_KEY *key = NULL;
    const EC_GROUP *group = NULL;
    BIGNUM *priv_key_bn = NULL;
    EC_POINT *pub_point = NULL;
    unsigned char pub_key[65];
    int pub_len;
    
    if (!(key = EC_KEY_new_by_curve_name(NID_secp256k1))) {
        return 0;
    }
    
    priv_key_bn = BN_new();
    BN_set_word(priv_key_bn, privkey);
    
    if (!EC_KEY_set_private_key(key, priv_key_bn)) {
        BN_free(priv_key_bn);
        EC_KEY_free(key);
        return 0;
    }
    
    group = EC_KEY_get0_group(key);
    pub_point = EC_POINT_new(group);
    
    if (!EC_POINT_mul(group, pub_point, priv_key_bn, NULL, NULL, NULL)) {
        EC_POINT_free(pub_point);
        BN_free(priv_key_bn);
        EC_KEY_free(key);
        return 0;
    }
    
    EC_KEY_set_public_key(key, pub_point);
    
    // Uncompressed public key format (0x04 + x + y)
    pub_len = EC_KEY_key2buf(key, POINT_CONVERSION_UNCOMPRESSED, &pub_key, NULL);
    if (pub_len <= 0) {
        EC_POINT_free(pub_point);
        BN_free(priv_key_bn);
        EC_KEY_free(key);
        return 0;
    }
    
    // Compute hash160 of public key
    hash160(pub_key, pub_len, hash160_out);
    
    EC_POINT_free(pub_point);
    BN_free(priv_key_bn);
    EC_KEY_free(key);
    return 1;
}

/** Thread function for brute-force search */
void *solver_thread(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    unsigned char computed_hash[20];
    unsigned char target_hash[20];
    unsigned long key;
    unsigned long count = 0;
    
    hex_to_bytes(args->target_hash160, target_hash, 20);
    
    printf("[Thread %d] Searching bits 1-32 of range [%lu, %lu)\n", 
           args->thread_id, args->start_key, args->end_key);
    
    for (key = args->start_key; key < args->end_key && !args->found; key++) {
        if (get_hash160(key, computed_hash)) {
            if (memcmp(computed_hash, target_hash, 20) == 0) {
                args->found = 1;
                args->solution_key = key;
                printf("\n[Thread %d] ✓ FOUND KEY: 0x%lx (%lu)\n", 
                       args->thread_id, key, key);
                return NULL;
            }
        }
        
        count++;
        if (count % 10000000 == 0) {
            printf("[Thread %d] Checked %lu keys (~%.1f%% of bit space)\n", 
                   args->thread_id, count, 
                   (double)count * 100.0 / (args->end_key - args->start_key));
        }
    }
    
    printf("[Thread %d] Completed %lu keys - no solution found\n", 
           args->thread_id, count);
    return NULL;
}

/** Main solver */
int main(int argc, char *argv[]) {
    int bit_num = 32;  // Default: solve bit 32 (easy test case)
    int num_threads = 4;
    unsigned long search_space;
    unsigned long keys_per_thread;
    pthread_t threads[MAX_THREADS];
    thread_args_t thread_data[MAX_THREADS];
    int i;
    
    // Bitcoin puzzle #66 hash160 (for testing)
    const char *target_hash160_test = "a4b0f18ae0d3ddfc72c7a78a67a07757";
    const char *target_hash160 = target_hash160_test;
    
    if (argc > 1) {
        bit_num = atoi(argv[1]);
    }
    if (argc > 2) {
        num_threads = atoi(argv[2]);
    }
    
    if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
    
    // Calculate search space for this bit
    // For bit N, search space is 2^(N-1) to 2^N
    if (bit_num <= 32) {
        search_space = (1UL << bit_num);
        keys_per_thread = search_space / num_threads;
    } else {
        fprintf(stderr, "Error: Bit %d is beyond 32-bit search space in this demo\n", bit_num);
        fprintf(stderr, "Use GPU acceleration (CUDA) for bits > 32\n");
        return 1;
    }
    
    printf("========================================\n");
    printf("Bitcoin Puzzle Solver (secp256k1)\n");
    printf("========================================\n");
    printf("Target Hash160: %s\n", target_hash160);
    printf("Search Range: Bit %d (2^%d to 2^%d)\n", bit_num, bit_num-1, bit_num);
    printf("Search Space: 2^%d = %lu keys\n", bit_num, search_space);
    printf("Threads: %d\n", num_threads);
    printf("Keys per thread: %lu\n", keys_per_thread);
    printf("========================================\n\n");
    
    time_t start_time = time(NULL);
    
    // Create solver threads
    for (i = 0; i < num_threads; i++) {
        thread_data[i].bit_num = bit_num;
        thread_data[i].start_key = i * keys_per_thread;
        thread_data[i].end_key = (i == num_threads - 1) ? search_space : (i + 1) * keys_per_thread;
        thread_data[i].target_hash160 = target_hash160;
        thread_data[i].thread_id = i;
        thread_data[i].found = 0;
        thread_data[i].solution_key = 0;
        
        pthread_create(&threads[i], NULL, solver_thread, &thread_data[i]);
    }
    
    // Wait for all threads
    for (i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        if (thread_data[i].found) {
            time_t end_time = time(NULL);
            printf("\n========================================\n");
            printf("SOLUTION FOUND!\n");
            printf("Private Key: 0x%lx\n", thread_data[i].solution_key);
            printf("Time Taken: %ld seconds\n", end_time - start_time);
            printf("========================================\n");
            return 0;
        }
    }
    
    time_t end_time = time(NULL);
    printf("\n========================================\n");
    printf("Search Complete - No solution found\n");
    printf("Time Taken: %ld seconds\n", end_time - start_time);
    printf("========================================\n");
    
    return 1;
}
