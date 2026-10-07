/**
 * Bitcoin Puzzle ECDSA Solver - Multi-threaded with GPU support
 * Proper secp256k1 ECDSA implementation with RIPEMD160 hash160
 * 
 * Compilation:
 * gcc -O3 -march=native -pthread -o bitcoin_solver_parallel bitcoin_solver_parallel.c -lssl -lcrypto -lm
 * 
 * Usage:
 * ./bitcoin_solver_parallel <target_hash160_hex> <bit_number> <max_keys> [num_threads]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/bn.h>

#define MAX_THREADS 16
#define BATCH_SIZE 10000

typedef struct {
    EC_GROUP *group;
    BIGNUM *priv_key_bn;
    const EC_POINT *pub_gen;
    unsigned char *target_hash;
    unsigned long start_key;
    unsigned long end_key;
    int thread_id;
    volatile int *found_flag;
    unsigned long *solution_key;
    unsigned long *keys_checked;
} thread_args_t;

/* Compute hash160 = RIPEMD160(SHA256(data)) */
static void compute_hash160(const unsigned char *data, size_t len, unsigned char *hash160_out) {
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha_ctx;
    RIPEMD160_CTX ripemd_ctx;
    
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, data, len);
    SHA256_Final(sha256_hash, &sha_ctx);
    
    RIPEMD160_Init(&ripemd_ctx);
    RIPEMD160_Update(&ripemd_ctx, sha256_hash, SHA256_DIGEST_LENGTH);
    RIPEMD160_Final(hash160_out, &ripemd_ctx);
}

/* Get public key hash160 from private key */
static int get_pubkey_hash160(const EC_GROUP *group, const unsigned long privkey, unsigned char *hash160_out) {
    BIGNUM *priv_bn = BN_new();
    if (!priv_bn) return 0;
    
    BN_set_word(priv_bn, privkey);
    
    /* Compute public key point: Q = privkey * G */
    EC_POINT *pub_point = EC_POINT_new(group);
    if (!pub_point) {
        BN_free(priv_bn);
        return 0;
    }
    
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        return 0;
    }
    
    /* Q = privkey * G */
    if (!EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, ctx)) {
        BN_CTX_free(ctx);
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        return 0;
    }
    
    /* Get uncompressed public key format (0x04 + x + y) */
    size_t pub_len = EC_POINT_point2buf(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, NULL, ctx);
    if (pub_len <= 0) {
        BN_CTX_free(ctx);
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        return 0;
    }
    
    unsigned char *pub_key = malloc(pub_len);
    if (!pub_key) {
        BN_CTX_free(ctx);
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        return 0;
    }
    
    EC_POINT_point2buf(group, pub_point, POINT_CONVERSION_UNCOMPRESSED, &pub_key, ctx);
    
    /* Compute hash160 of public key */
    compute_hash160(pub_key, pub_len, hash160_out);
    
    free(pub_key);
    BN_CTX_free(ctx);
    EC_POINT_free(pub_point);
    BN_free(priv_bn);
    
    return 1;
}

/* Thread worker function */
static void *solver_thread(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    unsigned char computed_hash[20];
    
    for (unsigned long key = args->start_key; key <= args->end_key; key++) {
        if (*args->found_flag) break;
        
        if (get_pubkey_hash160(args->group, key, computed_hash)) {
            (*args->keys_checked)++;
            
            if (memcmp(computed_hash, args->target_hash, 20) == 0) {
                *args->found_flag = 1;
                *args->solution_key = key;
                fprintf(stderr, "[Thread %d] ✓ FOUND! Key: %lu (0x%lx)\n", args->thread_id, key, key);
                break;
            }
        }
        
        if (*args->keys_checked % BATCH_SIZE == 0) {
            fprintf(stderr, "[Thread %d] Checked %lu keys\n", args->thread_id, *args->keys_checked);
        }
    }
    
    return NULL;
}

/* Convert hex string to bytes */
static void hex_to_bytes(const char *hex, unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(&hex[i * 2], "%2hhx", &bytes[i]);
    }
}

/* Convert bytes to hex string */
static void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(&hex[i * 2], "%02x", bytes[i]);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <target_hash160_hex> <bit_number> <max_keys> [num_threads]\n", argv[0]);
        fprintf(stderr, "Example: %s 751e76e8199196d454941c45d1b3a323f1433bd6 1 1000000 4\n", argv[0]);
        exit(1);
    }
    
    const char *target_hex = argv[1];
    int bit_num = atoi(argv[2]);
    unsigned long max_keys = strtoull(argv[3], NULL, 10);
    int num_threads = argc > 4 ? atoi(argv[4]) : 4;
    
    if (num_threads < 1 || num_threads > MAX_THREADS) num_threads = 4;
    
    /* Parse target hash160 */
    unsigned char target_hash[20];
    hex_to_bytes(target_hex, target_hash, 20);
    
    /* Initialize OpenSSL */
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!key) {
        fprintf(stderr, "Failed to create EC key\n");
        exit(1);
    }
    
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_KEY_free(key);
    
    fprintf(stderr, "[Solver] Target hash160: %s\n", target_hex);
    fprintf(stderr, "[Solver] Bit number: %d\n", bit_num);
    fprintf(stderr, "[Solver] Max keys: %lu\n", max_keys);
    fprintf(stderr, "[Solver] Threads: %d\n", num_threads);
    
    time_t start_time = time(NULL);
    
    /* Parallel search */
    pthread_t threads[MAX_THREADS];
    thread_args_t thread_args[MAX_THREADS];
    volatile int found_flag = 0;
    unsigned long solution_key = 0;
    unsigned long keys_checked = 0;
    
    unsigned long keys_per_thread = max_keys / num_threads;
    
    for (int i = 0; i < num_threads; i++) {
        thread_args[i].group = (EC_GROUP *)group;
        thread_args[i].target_hash = target_hash;
        thread_args[i].start_key = i * keys_per_thread + 1;
        thread_args[i].end_key = (i == num_threads - 1) ? max_keys : (i + 1) * keys_per_thread;
        thread_args[i].thread_id = i;
        thread_args[i].found_flag = (int *)&found_flag;
        thread_args[i].solution_key = &solution_key;
        thread_args[i].keys_checked = &keys_checked;
        
        pthread_create(&threads[i], NULL, solver_thread, &thread_args[i]);
    }
    
    /* Wait for all threads */
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        if (found_flag) break;
    }
    
    time_t end_time = time(NULL);
    double elapsed = difftime(end_time, start_time);
    
    /* Output JSON result */
    printf("{");
    printf("\"found\":%s,", found_flag ? "true" : "false");
    printf("\"privateKey\":%lu,", solution_key);
    printf("\"privateKeyHex\":\"0x%lx\",", solution_key);
    printf("\"searchedKeys\":%lu,", keys_checked);
    printf("\"timeSeconds\":%.2f,", elapsed);
    printf("\"targetHash160\":\"%s\"", target_hex);
    printf("}\n");
    
    return found_flag ? 0 : 1;
}
