#include <cuda_runtime.h>
#include "petya.h"

#define SHL(x, s) ((uint32_t) ((x) << ((s) & 31)))
#define SHR(x, s) ((uint32_t) ((x) >> (32 - ((s) & 31))))
#define ROTL(x, s) ((uint32_t) (SHL((x), (s)) | SHR((x), (s))))


// Cuda Code
__global__ void
vectorAdd(const float *A, const float *B, float *C, int numElements)
{
    int i = blockDim.x * blockIdx.x + threadIdx.x;

    if (i < numElements)
    {
        C[i] = A[i] + B[i];
    }
}


__global__ void gpu_crypt_and_validate(uint8_t *key,
                           
                            uint8_t nonce[8],
                            uint32_t si,
                            uint8_t *buf,
                            uint32_t buflen,
                            bool *isValid,
		            int nrTotal)
{
  int threadNr = blockDim.x * blockIdx.x + threadIdx.x;

  if (threadNr>=nrTotal) return;

  (*isValid) = false;


  if (threadNr!=0)  return;
  
   
  uint8_t keystream[64];
  uint8_t n[16] = { 0 };
  uint32_t i;

  for (i = 0; i < 8; ++i)
    n[i] = nonce[i];

  if (si % 64 != 0) {
    // s20_rev_littleendian(n+8, si / 64);
    (n+8)[0] = (si / 64);
    (n+8)[1] = (si / 64)>>8;
    (n+8)[2] = (si / 64)>>16;
    (n+8)[3] = (si / 64)>>24;
    
    // --------------------------------
    // s20_expand16(key, n, keystream);
    // --------------------------------    
    
      int i, j;
  uint8_t t[4][4] = {
    { 'e', 'x', 'p', 'a' },
    { 'n', 'd', ' ', '1' },
    { '6', '-', 'b', 'y' },
    { 't', 'e', ' ', 'k' }
  };

  for (i = 0; i < 64; i += 20)
    for (j = 0; j < 4; ++j)
      keystream[i + j] = t[i / 20][j];

  for (i = 0; i < 16; ++i) {
    keystream[4+i]  = key[i];
    keystream[44+i] = key[i];
    keystream[24+i] = n[i];
  }

  // ____________________
  // s20_hash(keystream);
  // --------------------
  
//    int i;
  uint32_t x[16];
  uint32_t z[16];

  for (i = 0; i < 16; ++i) {
        
    // s20_littleendian
    uint8_t* result = keystream + (4 * i);
    x[i] = z[i] = (int16_t)(result[0]+(result[1]<<8)); //  s20_littleendian(seq + (4 * i));
  }

  for (i = 0; i < 10; ++i) {
//    s20_doubleround(z);
    
  // ColumnRound
  // s20_quarterround(&x[0], &x[4], &x[8], &x[12]);
  
  z[4] =  z[4]  ^ ROTL(z[0]  + z[12], 7);
  z[8] =  z[8]  ^ ROTL(z[4]  + z[0], 9);
  z[12] = z[12] ^ ROTL(z[8]  + z[4], 13);
  z[0] =  z[0]  ^ ROTL(z[12] + z[8], 18);
  
  // s20_quarterround(&x[5], &x[9], &x[13], &x[1]);
  z[9] =  z[9]  ^ ROTL(z[5]  + z[1], 7);
  z[13] = z[13] ^ ROTL(z[9]  + z[5], 9);
  z[1] =  z[1]  ^ ROTL(z[13] + z[9], 13);
  z[5] =  z[5]  ^ ROTL(z[1]  + z[13], 18);
  
  // s20_quarterround(&x[10], &x[14], &x[2], &x[6]);
  z[14]=  z[14] ^ ROTL(z[10] + z[6], 7);
  z[2] =  z[2]  ^ ROTL(z[14] + z[10], 9);
  z[6] =  z[6]  ^ ROTL(z[2]  + z[14], 13);
  z[10] = z[10] ^ ROTL(z[6]  + z[2], 18);
  
  // s20_quarterround(&x[15], &x[3], &x[7], &x[11]);
  z[3] =  z[3]  ^ ROTL(z[15] + z[11], 7);
  z[7] =  z[7]  ^ ROTL(z[3]  + z[15], 9);
  z[11] = z[11] ^ ROTL(z[7]  + z[3], 13);
  z[15] = z[15] ^ ROTL(z[11] + z[7], 18);
  
  // Rowround
  // s20_quarterround(&y[0], &y[1], &y[2], &y[3]);
  z[1] = z[1] ^ ROTL(z[0]+  z[3], 7);
  z[2] = z[2] ^ ROTL(z[1] + z[0], 9);
  z[3] = z[3] ^ ROTL(z[2] + z[1], 13);
  z[0] = z[0] ^ ROTL(z[3] + z[2], 18);
  
  // s20_quarterround(&y[5], &y[6], &y[7], &y[4]);
  z[6] = z[6] ^ ROTL(z[5] + z[4], 7);
  z[7] = z[7] ^ ROTL(z[6] + z[5], 9);
  z[4] = z[4] ^ ROTL(z[7] + z[6], 13);
  z[5] = z[5] ^ ROTL(z[4] + z[7], 18);
  
  // s20_quarterround(&y[10], &y[11], &y[8], &y[9]);
  z[11] = z[11] ^ ROTL(z[10] + z[9], 7);
  z[8] =  z[8]  ^ ROTL(z[11] + z[10], 9);
  z[9] =  z[9]  ^ ROTL(z[8] +  z[11], 13);
  z[10] = z[10] ^ ROTL(z[9] +  z[8], 18);
  
  // s20_quarterround(&y[15], &y[12], &y[12], &y[14]);
  z[12] = z[12] ^ ROTL(z[15] + z[14], 7);
  z[12] = z[12] ^ ROTL(z[12] + z[15], 9);
  z[14] = z[14] ^ ROTL(z[12] + z[12], 13);
  z[15] = z[15] ^ ROTL(z[14] + z[12], 18);
  }

  for (i = 0; i < 16; ++i) {
    z[i] += x[i];
    // s20_rev_littleendian(seq + (4 * i), z[i]);
      (keystream + (4 * i))[0] = z[i];
      (keystream + (4 * i))[1] = z[i] >> 8;
      (keystream + (4 * i))[2] = z[i] >> 16;
      (keystream + (4 * i))[3] = z[i] >> 24;
  }
  

    
  }

  for (i = 0; i < buflen; ++i) {
    if ((si + i) % 64 == 0) {
      //s20_rev_littleendian(n+8, ((si + i) / 64));
      (n+8)[0] = ((si + i) / 64);
      (n+8)[1] = ((si + i) / 64)>>8;
      (n+8)[2] = ((si + i) / 64)>>16;
      (n+8)[3] = ((si + i) / 64)>>24;
          
      // s20_expand16(key, n, keystream);
      
        int i, j;
  uint8_t t[4][4] = {
    { 'e', 'x', 'p', 'a' },
    { 'n', 'd', ' ', '1' },
    { '6', '-', 'b', 'y' },
    { 't', 'e', ' ', 'k' }
  };

  for (i = 0; i < 64; i += 20)
    for (j = 0; j < 4; ++j)
      keystream[i + j] = t[i / 20][j];

  for (i = 0; i < 16; ++i) {
    keystream[4+i]  = key[i];
    keystream[44+i] = key[i];
    keystream[24+i] = n[i];
  }

  // ____________________
  // s20_hash(keystream);
  // --------------------
  
//    int i;
  uint32_t x[16];
  uint32_t z[16];

  for (i = 0; i < 16; ++i) {
        
    // s20_littleendian
    uint8_t* result = keystream + (4 * i);
    x[i] = z[i] = (int16_t)(result[0]+(result[1]<<8)); //  s20_littleendian(seq + (4 * i));
  }

  for (i = 0; i < 10; ++i) {
    //    s20_doubleround(z);
        
      // ColumnRound
      // s20_quarterround(&x[0], &x[4], &x[8], &x[12]);
      
      z[4] =  z[4]  ^ ROTL(z[0]  + z[12], 7);
      z[8] =  z[8]  ^ ROTL(z[4]  + z[0], 9);
      z[12] = z[12] ^ ROTL(z[8]  + z[4], 13);
      z[0] =  z[0]  ^ ROTL(z[12] + z[8], 18);
      
      // s20_quarterround(&x[5], &x[9], &x[13], &x[1]);
      z[9] =  z[9]  ^ ROTL(z[5]  + z[1], 7);
      z[13] = z[13] ^ ROTL(z[9]  + z[5], 9);
      z[1] =  z[1]  ^ ROTL(z[13] + z[9], 13);
      z[5] =  z[5]  ^ ROTL(z[1]  + z[13], 18);
      
      // s20_quarterround(&x[10], &x[14], &x[2], &x[6]);
      z[14]=  z[14] ^ ROTL(z[10] + z[6], 7);
      z[2] =  z[2]  ^ ROTL(z[14] + z[10], 9);
      z[6] =  z[6]  ^ ROTL(z[2]  + z[14], 13);
      z[10] = z[10] ^ ROTL(z[6]  + z[2], 18);
      
      // s20_quarterround(&x[15], &x[3], &x[7], &x[11]);
      z[3] =  z[3]  ^ ROTL(z[15] + z[11], 7);
      z[7] =  z[7]  ^ ROTL(z[3]  + z[15], 9);
      z[11] = z[11] ^ ROTL(z[7]  + z[3], 13);
      z[15] = z[15] ^ ROTL(z[11] + z[7], 18);
      
      // Rowround
      // s20_quarterround(&y[0], &y[1], &y[2], &y[3]);
      z[1] = z[1] ^ ROTL(z[0]+  z[3], 7);
      z[2] = z[2] ^ ROTL(z[1] + z[0], 9);
      z[3] = z[3] ^ ROTL(z[2] + z[1], 13);
      z[0] = z[0] ^ ROTL(z[3] + z[2], 18);
      
      // s20_quarterround(&y[5], &y[6], &y[7], &y[4]);
      z[6] = z[6] ^ ROTL(z[5] + z[4], 7);
      z[7] = z[7] ^ ROTL(z[6] + z[5], 9);
      z[4] = z[4] ^ ROTL(z[7] + z[6], 13);
      z[5] = z[5] ^ ROTL(z[4] + z[7], 18);
      
      // s20_quarterround(&y[10], &y[11], &y[8], &y[9]);
      z[11] = z[11] ^ ROTL(z[10] + z[9], 7);
      z[8] =  z[8]  ^ ROTL(z[11] + z[10], 9);
      z[9] =  z[9]  ^ ROTL(z[8] +  z[11], 13);
      z[10] = z[10] ^ ROTL(z[9] +  z[8], 18);
      
      // s20_quarterround(&y[15], &y[12], &y[12], &y[14]);
      z[12] = z[12] ^ ROTL(z[15] + z[14], 7);
      z[12] = z[12] ^ ROTL(z[12] + z[15], 9);
      z[14] = z[14] ^ ROTL(z[12] + z[12], 13);
      z[15] = z[15] ^ ROTL(z[14] + z[12], 18);
      }
    
      for (i = 0; i < 16; ++i) {
        z[i] += x[i];
        // s20_rev_littleendian(seq + (4 * i), z[i]);
          (keystream + (4 * i))[0] = z[i];
          (keystream + (4 * i))[1] = z[i] >> 8;
          (keystream + (4 * i))[2] = z[i] >> 16;
          (keystream + (4 * i))[3] = z[i] >> 24;
      }
  
    }
    buf[i] ^= keystream[(si + i) % 64];
  }
  
  // Validate Crypto Result 
  for (size_t i = 0; i < VERIBUF_SIZE; i++) {
     if (buf[i] != VERIFICATION_CHAR) {
        (*isValid) = false;
        return;
    }
  }
  
  *isValid = true;
  
}

void make_random_key_gpu(char* key)
{
    size_t charset_len = strlen(KEY_CHARSET);

    memset(key, 'x', KEY_SIZE);

    for (int i = 0; i < KEY_SIZE; i+=4) {
        size_t rand_i1 = rand() % charset_len;
        size_t rand_i2 = rand() % charset_len;
        key[i] = KEY_CHARSET[rand_i1];
        key[i+1] = KEY_CHARSET[rand_i2];
    }
    key[KEY_SIZE] = 0;
}


void initializeAndCalculate(uint8_t nonce_hc[8],  char *verificationBuffer_hc) {

    int n=2048*2048;

    char p_key[KEY_SIZE+1];
    char *key = p_key;               


    cudaError_t err = cudaSuccess;
    
    uint8_t *verifbuf_test_dc = NULL;
    char veribuf_test_local[VERIBUF_SIZE];
         
    err = cudaMalloc((void **)&verifbuf_test_dc, VERIBUF_SIZE);
    
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to allocate device memory (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }


    err = cudaMemcpy(verifbuf_test_dc, verificationBuffer_hc, VERIBUF_SIZE, cudaMemcpyHostToDevice);
    
    err = cudaGetLastError();

    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to copy verification buffer from host to gpu (error code %s)!\n",      cudaGetErrorString(err));
        exit(EXIT_FAILURE);

    }
    
    
    //   if (s20_crypt((uint8_t *) key, S20_KEYLEN_128, (uint8_t *) nonce, 0, (uint8_t *) veribuf_test, VERIBUF_SIZE) == S20_FAILURE) {

                    
    uint32_t si_hc;
    uint8_t *buf_hc;
    uint32_t buflen_hc;
    
    uint8_t *key_dc;                       
    uint8_t *nonce_dc;
    uint32_t si_dc = 0;
    uint8_t *buf_dc;
    uint32_t buflen_dc;
    
    
    err = cudaMalloc((void **)&key_dc, KEY_SIZE);
    
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to allocate device memory for key (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }


    err = cudaMalloc((void **)&nonce_dc, 8);
    
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to allocate device memory for nonce (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    
    

    
    
    err = cudaMemcpy(nonce_dc, nonce_hc, 8, cudaMemcpyHostToDevice);
    
    err = cudaGetLastError();

    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to copy nonce from host to gpu (error code %s)!\n",      cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    bool result_hc;
    bool *result_dc;
    
    err = cudaMalloc((void **)&result_dc, sizeof(bool));
    
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to allocate device memory for isValid Result (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }


    make_random_key_gpu(key);
    err = cudaMemcpy(key_dc, (uint8_t *) key, KEY_SIZE, cudaMemcpyHostToDevice);
    
    err = cudaGetLastError();

    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to copy key from host to gpu (error code %s)!\n",      cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
                            
    gpu_crypt_and_validate<<<1, 1024>>>(key_dc, 
                                     nonce_dc, 
                                     si_dc, 
                                     verifbuf_test_dc, 
                                     VERIBUF_SIZE, 
                                     result_dc,n );
    
    
    
err = cudaGetLastError();

    if (err != cudaSuccess)
    {
        fprintf(stderr, "error starting thread on gpu (error code %s)!\n",      cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    
    err = cudaMemcpy(&result_hc, 
                     result_dc, 
                     sizeof(bool), 
                     cudaMemcpyDeviceToHost);

    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to copy memory from device to host (error code %s)!\n",      cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    
    if (!result_hc) {
        printf("Cuda Result is false");
    } else {
        printf("Cuda Result is true");
    }
    
    /*
    err = cudaMemcpy(veribuf_test_local, verifbuf_test_dc, VERIBUF_SIZE, cudaMemcpyDeviceToHost);

    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to copy memory from device to host (error code %s)!\n",      cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    */
    

    // Free device global memory
     err = cudaFree(result_dc);
    
    
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to free device memory (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }


    
    
    err = cudaFree(verifbuf_test_dc);
    
    
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Failed to free device memory (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    
}


/*
static int16_t void s20_littleendian(uint8_t *b)
{
  return b[0] +
         (b[1] << 8);
}
*/

/*
inline static void s20_rev_littleendian(uint8_t *b, uint32_t w)
{
  b[0] = w;
  b[1] = w >> 8;
  b[2] = w >> 16;
  b[3] = w >> 24;
}
*/

/*
inline static uint32_t rotl(uint32_t value, int shift)
{
  return (value << shift) | (value >> (32 - shift));
}
*/

/*
inline static void s20_quarterround(uint32_t *y0, uint32_t *y1, uint32_t *y2, uint32_t *y3)
{
  *y1 = *y1 ^ rotl(*y0 + *y3, 7);
  *y2 = *y2 ^ rotl(*y1 + *y0, 9);
  *y3 = *y3 ^ rotl(*y2 + *y1, 13);
  *y0 = *y0 ^ rotl(*y3 + *y2, 18);
}
*/

/*
inline static void s20_rowround(uint32_t y[16])
{
  s20_quarterround(&y[0], &y[1], &y[2], &y[3]);
  s20_quarterround(&y[5], &y[6], &y[7], &y[4]);
  s20_quarterround(&y[10], &y[11], &y[8], &y[9]);
  s20_quarterround(&y[15], &y[12], &y[13], &y[14]);
}

inline static void s20_columnround(uint32_t x[16])
{
  s20_quarterround(&x[0], &x[4], &x[8], &x[12]);
  s20_quarterround(&x[5], &x[9], &x[13], &x[1]);
  s20_quarterround(&x[10], &x[14], &x[2], &x[6]);
  s20_quarterround(&x[15], &x[3], &x[7], &x[11]);
}
*/

/*
inline static void s20_doubleround(uint32_t x[16])
{
//  s20_columnround(x);
//  s20_rowround(x);
}
*/

/*
inline static void s20_hash(uint8_t seq[64])
{
  int i;
  uint32_t x[16];
  uint32_t z[16];

  for (i = 0; i < 16; ++i) {
        
    // s20_littleendian
    uint8_t* result = seq + (4 * i);
    x[i] = z[i] = (int16_t)(result[0]+(result[1]<<8)); //  s20_littleendian(seq + (4 * i));
  }

  for (i = 0; i < 10; ++i) {
//    s20_doubleround(z);
    
  // ColumnRound
  // s20_quarterround(&x[0], &x[4], &x[8], &x[12]);
  
  z[4] =  z[4]  ^ rotl(z[0]  + z[12], 7);
  z[8] =  z[8]  ^ rotl(z[4]  + z[0], 9);
  z[12] = z[12] ^ rotl(z[8]  + z[4], 13);
  z[0] =  z[0]  ^ rotl(z[12] + z[8], 18);
  
  // s20_quarterround(&x[5], &x[9], &x[13], &x[1]);
  z[9] =  z[9]  ^ rotl(z[5]  + z[1], 7);
  z[13] = z[13] ^ rotl(z[9]  + z[5], 9);
  z[1] =  z[1]  ^ rotl(z[13] + z[9], 13);
  z[5] =  z[5]  ^ rotl(z[1]  + z[13], 18);
  
  // s20_quarterround(&x[10], &x[14], &x[2], &x[6]);
  z[14]=  z[14] ^ rotl(z[10] + z[6], 7);
  z[2] =  z[2]  ^ rotl(z[14] + z[10], 9);
  z[6] =  z[6]  ^ rotl(z[2]  + z[14], 13);
  z[10] = z[10] ^ rotl(z[6]  + z[2], 18);
  
  // s20_quarterround(&x[15], &x[3], &x[7], &x[11]);
  z[3] =  z[3]  ^ rotl(z[15] + z[11], 7);
  z[7] =  z[7]  ^ rotl(z[3]  + z[15], 9);
  z[11] = z[11] ^ rotl(z[7]  + z[3], 13);
  z[15] = z[15] ^ rotl(z[11] + z[7], 18);
  
  // Rowround
  // s20_quarterround(&y[0], &y[1], &y[2], &y[3]);
  z[1] = z[1] ^ rotl(z[0]+  z[3], 7);
  z[2] = z[2] ^ rotl(z[1] + z[0], 9);
  z[3] = z[3] ^ rotl(z[2] + z[1], 13);
  z[0] = z[0] ^ rotl(z[3] + z[2], 18);
  
  // s20_quarterround(&y[5], &y[6], &y[7], &y[4]);
  z[6] = z[6] ^ rotl(z[5] + z[4], 7);
  z[7] = z[7] ^ rotl(z[6] + z[5], 9);
  z[4] = z[4] ^ rotl(z[7] + z[6], 13);
  z[5] = z[5] ^ rotl(z[4] + z[7], 18);
  
  // s20_quarterround(&y[10], &y[11], &y[8], &y[9]);
  z[11] = z[11] ^ rotl(z[10] + z[9], 7);
  z[8] =  z[8]  ^ rotl(z[11] + z[10], 9);
  z[9] =  z[9]  ^ rotl(z[8] +  z[11], 13);
  z[10] = z[10] ^ rotl(z[9] +  z[8], 18);
  
  // s20_quarterround(&y[15], &y[12], &y[12], &y[14]);
  z[12] = z[12] ^ rotl(z[15] + z[14], 7);
  z[12] = z[12] ^ rotl(z[12] + z[15], 9);
  z[14] = z[14] ^ rotl(z[12] + z[12], 13);
  z[15] = z[15] ^ rotl(z[14] + z[12], 18);
  }

  for (i = 0; i < 16; ++i) {
    z[i] += x[i];
    // s20_rev_littleendian(seq + (4 * i), z[i]);
      (seq + (4 * i))[0] = z[i];
      (seq + (4 * i))[1] = z[i] >> 8;
      (seq + (4 * i))[2] = z[i] >> 16;
      (seq + (4 * i))[3] = z[i] >> 24;
  }
}
*/

/*
void s20_expand16(uint8_t *key,
                         uint8_t n[16],
                         uint8_t keystream[64])
{
  int i, j;
  uint8_t t[4][4] = {
    { 'e', 'x', 'p', 'a' },
    { 'n', 'd', ' ', '1' },
    { '6', '-', 'b', 'y' },
    { 't', 'e', ' ', 'k' }
  };

  for (i = 0; i < 64; i += 20)
    for (j = 0; j < 4; ++j)
      keystream[i + j] = t[i / 20][j];

  for (i = 0; i < 16; ++i) {
    keystream[4+i]  = key[i];
    keystream[44+i] = key[i];
    keystream[24+i] = n[i];
  }

  // ____________________
  // s20_hash(keystream);
  // --------------------
  
//    int i;
  uint32_t x[16];
  uint32_t z[16];

  for (i = 0; i < 16; ++i) {
        
    // s20_littleendian
    uint8_t* result = keystream + (4 * i);
    x[i] = z[i] = (int16_t)(result[0]+(result[1]<<8)); //  s20_littleendian(seq + (4 * i));
  }

  for (i = 0; i < 10; ++i) {
//    s20_doubleround(z);
    
  // ColumnRound
  // s20_quarterround(&x[0], &x[4], &x[8], &x[12]);
  
  z[4] =  z[4]  ^ ROTL(z[0]  + z[12], 7);
  z[8] =  z[8]  ^ ROTL(z[4]  + z[0], 9);
  z[12] = z[12] ^ ROTL(z[8]  + z[4], 13);
  z[0] =  z[0]  ^ ROTL(z[12] + z[8], 18);
  
  // s20_quarterround(&x[5], &x[9], &x[13], &x[1]);
  z[9] =  z[9]  ^ ROTL(z[5]  + z[1], 7);
  z[13] = z[13] ^ ROTL(z[9]  + z[5], 9);
  z[1] =  z[1]  ^ ROTL(z[13] + z[9], 13);
  z[5] =  z[5]  ^ ROTL(z[1]  + z[13], 18);
  
  // s20_quarterround(&x[10], &x[14], &x[2], &x[6]);
  z[14]=  z[14] ^ ROTL(z[10] + z[6], 7);
  z[2] =  z[2]  ^ ROTL(z[14] + z[10], 9);
  z[6] =  z[6]  ^ ROTL(z[2]  + z[14], 13);
  z[10] = z[10] ^ ROTL(z[6]  + z[2], 18);
  
  // s20_quarterround(&x[15], &x[3], &x[7], &x[11]);
  z[3] =  z[3]  ^ ROTL(z[15] + z[11], 7);
  z[7] =  z[7]  ^ ROTL(z[3]  + z[15], 9);
  z[11] = z[11] ^ ROTL(z[7]  + z[3], 13);
  z[15] = z[15] ^ ROTL(z[11] + z[7], 18);
  
  // Rowround
  // s20_quarterround(&y[0], &y[1], &y[2], &y[3]);
  z[1] = z[1] ^ ROTL(z[0]+  z[3], 7);
  z[2] = z[2] ^ ROTL(z[1] + z[0], 9);
  z[3] = z[3] ^ ROTL(z[2] + z[1], 13);
  z[0] = z[0] ^ ROTL(z[3] + z[2], 18);
  
  // s20_quarterround(&y[5], &y[6], &y[7], &y[4]);
  z[6] = z[6] ^ ROTL(z[5] + z[4], 7);
  z[7] = z[7] ^ ROTL(z[6] + z[5], 9);
  z[4] = z[4] ^ ROTL(z[7] + z[6], 13);
  z[5] = z[5] ^ ROTL(z[4] + z[7], 18);
  
  // s20_quarterround(&y[10], &y[11], &y[8], &y[9]);
  z[11] = z[11] ^ ROTL(z[10] + z[9], 7);
  z[8] =  z[8]  ^ ROTL(z[11] + z[10], 9);
  z[9] =  z[9]  ^ ROTL(z[8] +  z[11], 13);
  z[10] = z[10] ^ ROTL(z[9] +  z[8], 18);
  
  // s20_quarterround(&y[15], &y[12], &y[12], &y[14]);
  z[12] = z[12] ^ ROTL(z[15] + z[14], 7);
  z[12] = z[12] ^ ROTL(z[12] + z[15], 9);
  z[14] = z[14] ^ ROTL(z[12] + z[12], 13);
  z[15] = z[15] ^ ROTL(z[14] + z[12], 18);
  }

  for (i = 0; i < 16; ++i) {
    z[i] += x[i];
    // s20_rev_littleendian(seq + (4 * i), z[i]);
      (keystream + (4 * i))[0] = z[i];
      (keystream + (4 * i))[1] = z[i] >> 8;
      (keystream + (4 * i))[2] = z[i] >> 16;
      (keystream + (4 * i))[3] = z[i] >> 24;
  }
  
  
}
*/
