
#ifndef __BNNABY_H_
#define __BNNABY_H_

#include "../../ABY/src/abycore/circuit/booleancircuits.h"
#include "../../ABY/src/abycore/circuit/arithmeticcircuits.h"
#include "../../ABY/src/abycore/circuit/circuit.h"
#include "../../ABY/src/abycore/aby/abyparty.h"
#include <math.h>
#include <cassert>

/**
 \param		role 		role played by the program which can be server or client part.
 \param 	address 	IP Address
 \param 	seclvl 		Security level
 \param 	nvals		Number of values
 \param 	bitlen		Bit length of the inputs
 \param 	nthreads	Number of threads
 \param		mt_alg		The algorithm for generation of multiplication triples
 \param 	sharing		Sharing type object
 \brief		This function is used for running a testing environment for solving the
 millionaire's problem
 */
uint32_t* BNN_Mnist_Secure_prediction(e_role role, char* address, uint16_t port, seclvl seclvl,
		uint32_t nvals, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing sharing, uint32_t num,
		uint32_t *W1, uint32_t W1nvals, uint32_t *input, uint32_t inputnvals,
		uint32_t *fullconnection, uint32_t fullconnectionnvals,
		uint32_t *middlefull, uint32_t middlefullnvals,
		uint32_t *s1, uint32_t s1nvals, uint32_t *t1, uint32_t t1nvals, 
		uint32_t *act, uint32_t actnvals, uint32_t *sign, uint32_t signnvals, 
		uint32_t *pos, uint32_t posnvals, 

		uint32_t *W2, uint32_t W2nvals, 
		uint32_t *fullconnection1, uint32_t fullconnection1nvals,
		uint32_t *middlefull1, uint32_t middlefull1nvals,
		uint32_t *s2, uint32_t s2nvals, uint32_t *t2, uint32_t t2nvals, 

		uint32_t *W3, uint32_t W3nvals, 
		uint32_t *fullconnection2, uint32_t fullconnection2nvals,
		uint32_t *middlefull2, uint32_t middlefull2nvals,
		uint32_t *s3, uint32_t s3nvals, uint32_t *t3, uint32_t t3nvals, uint32_t N);

int32_t Enc_circuit(e_role role, char* address, uint16_t port, seclvl seclvl,
		uint32_t nvals, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing sharing, uint32_t num, uint32_t *hidden3_2);


share* Fullconnection(share *s_mat1, share *s_mat2, share *s_mat3, share *s_mat4, uint32_t num, uint32_t col, uint32_t row, ArithmeticCircuit *ac);

share* Batchnorm(share *s_mat1, share *s_mat2, share *s_mat3, ArithmeticCircuit *ac);

share* Activation(share *s_mat1, share *s_mat2, share *s_mat3, ArithmeticCircuit *ac);


#endif /* __BNNABY_H_ */
