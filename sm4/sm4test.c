/*
 * SM4/SMS4 algorithm test programme
 * 2012-4-21
 * 对CBC模式进行了修改，保证了iv向量不改变，使该模式可用
 * 2019-3-12
 */

#include <string.h>
#include <stdio.h>
#include "sm4.h"

int main()
{
	unsigned char key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	unsigned char input[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	unsigned char iv[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
	unsigned char output[16];
	sm4_context ctx;
	unsigned long i;
	unsigned char temp[16];

	printf("Plain text	      : ");
	for (i = 0; i<16; i++)
		printf("%02x ", input[i]);
	printf("\n");

	//encrypt standard testing vector(ECB)
	sm4_setkey_enc(&ctx, key);
	sm4_crypt_ecb(&ctx, 1, 16, input, output);
	printf("Encryption result(ECB): ");
	for (i = 0; i<16; i++)
		printf("%02x ", output[i]);
	printf("\n");

	//decrypt testing
	sm4_setkey_dec(&ctx, key);
	sm4_crypt_ecb(&ctx, 0, 16, output, output);
	printf("Decryption result(ECB): ");
	for (i = 0; i<16; i++)
		printf("%02x ", output[i]);
	printf("\n");

	memcpy(temp, iv, sizeof(iv));  //必须加上这一句，否则在cbc加密过程中iv的值会发生改变，解密时再用到iv就会得出不正确的结果

	//encrypt standard testing vector
	sm4_setkey_enc(&ctx,key);
	sm4_crypt_cbc(&ctx,1,16,temp,input,output);
	printf("Encryption result(CBC): ");
	for(i=0;i<16;i++)
		printf("%02x ", output[i]);
	printf("\n");

	memcpy(temp, iv, sizeof(iv));

	//decrypt testing
	sm4_setkey_dec(&ctx,key);
	sm4_crypt_cbc(&ctx,0,16,temp,output,output);
	printf("Decryption result(CBC): ");
	for(i=0;i<16;i++)
		printf("%02x ", output[i]);
	printf("\n");

	/*
	//decrypt 1M times testing vector based on standards.
	i = 0;
	sm4_setkey_enc(&ctx,key);
	while (i<1000000) 
    {
		sm4_crypt_ecb(&ctx,1,16,input,input);
		i++;
    }
	printf("Encrypt 1M times result: ");
	for(i=0;i<16;i++)
		printf("%02x ", input[i]);
	printf("\n");
	*/

    return 0;
}
