#include "bnn_secure-prediction.h"
#include <iostream>
#include <sstream>
#include <string>
using namespace std;


/* Secure_prediction_1 */
uint32_t* TWN_Mnist_Secure_prediction(e_role role, char* address, uint16_t port, seclvl seclvl,
		uint32_t nvals, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing sharing, uint32_t num,
		uint32_t *W1, uint32_t W1nvals, uint32_t *input, uint32_t inputnvals,
		uint32_t *u1, uint32_t u1nvals,  

		uint32_t *W2, uint32_t W2nvals, 
		uint32_t *u2, uint32_t u2nvals, 

		uint32_t *W3, uint32_t W3nvals, 
		uint32_t *s3, uint32_t s3nvals, uint32_t *t3, uint32_t t3nvals, uint32_t N, 

		uint32_t *posids_W1, uint32_t *posids_W2, uint32_t *posids_W3, 
		uint32_t *W1posids_index, uint32_t *W2posids_index, uint32_t *W3posids_index
		) {

	/**
		Create the ABYParty object which defines the basis of all the
		 	 operations which are happening.	Operations performed are on the
		 	 basis of the role played by this object.
	*/

	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads,
			mt_alg, 15'000'000);

	/**
		Get to know all the sharing types available in the program.
	*/

	vector<Sharing*>& sharings = party->GetSharings();

	/**
		Create the circuit object on the basis of the sharing type
				being inputed.
	*/
	ArithmeticCircuit* circ = (ArithmeticCircuit*) sharings[sharing]->GetCircuitBuildRoutine();
	BooleanCircuit* yaocirc = (BooleanCircuit*)sharings[S_YAO]->GetCircuitBuildRoutine();
	BooleanCircuit* booleancirc = (BooleanCircuit*)sharings[S_BOOL]->GetCircuitBuildRoutine();


	/**
		Creating the share objects used in SecureBNN_ABY
	*/

	share *s_W1, *s_input, *s_hidden1_1, *s_u1, *s_hidden1_2, *s_hidden1_3,
	 *s_W2, *s_hidden2_1, *s_u2, *s_hidden2_2, *s_hidden2_3, 
	 *s_W3, *s_hidden3_1, *s_s3, *s_t3, *s_hidden3_2, *s_out;

	s_W1 = circ->PutSharedSIMDINGate(W1nvals, W1, bitlen);
	s_input = circ->PutSharedSIMDINGate(inputnvals, input, bitlen);
	s_u1 = circ->PutSharedSIMDINGate(u1nvals, u1, bitlen);

	s_W2 = circ->PutSharedSIMDINGate(W2nvals, W2, bitlen);
	s_u2 = circ->PutSharedSIMDINGate(u2nvals, u2, bitlen);

	s_W3 = circ->PutSharedSIMDINGate(W3nvals, W3, bitlen);
	s_s3 = circ->PutSharedSIMDINGate(s3nvals, s3, bitlen);
	s_t3 = circ->PutSharedSIMDINGate(t3nvals, t3, bitlen);


	/* The first layer */

	s_hidden1_1 = Fullconnection(s_W1, s_input, N*784, N, 784, bitlen, (ArithmeticCircuit*) circ, posids_W1, W1posids_index);
	s_hidden1_2 = BatchnormAct(s_hidden1_1, s_u1, (ArithmeticCircuit*) circ);
	s_hidden1_3 = Activation(s_hidden1_2, N, bitlen, (ArithmeticCircuit*) circ, (BooleanCircuit*) booleancirc, (BooleanCircuit*) yaocirc);

	/* The second layer */

	s_hidden2_1 = Fullconnection(s_W2, s_hidden1_3, N*N, N, N, bitlen, (ArithmeticCircuit*) circ, posids_W2, W2posids_index);
	s_hidden2_2 = BatchnormAct(s_hidden2_1, s_u2, (ArithmeticCircuit*) circ);
	s_hidden2_3 = Activation(s_hidden2_2, N, bitlen, (ArithmeticCircuit*) circ, (BooleanCircuit*) booleancirc, (BooleanCircuit*) yaocirc);

	/* The Third layer*/

	s_hidden3_1 = Fullconnection(s_W3, s_hidden2_3, 10*N, 10, N, bitlen, (ArithmeticCircuit*) circ, posids_W3, W3posids_index);
	s_hidden3_2 = Batchnorm(s_hidden3_1, s_s3, s_t3, (ArithmeticCircuit*) circ);

	/* make the pre-shared inputs to use in another circuit */	
	s_out = circ->PutSharedOUTGate(s_hidden3_2);

	/**
	 Executing the circuit using the ABYParty object evaluate the problem.
	 */

	party->ExecCircuit();

	/**
	 Get vector output.
	 */
	
	uint32_t out_bitlen, out_nvals, *out_vals;
	s_out->get_clear_value_vec(&out_vals, &out_bitlen, &out_nvals);
	
	delete party;


	/* return the share of output */
	return out_vals;

}

int32_t Enc_circuit(e_role role, char* address, uint16_t port, seclvl seclvl,
		uint32_t nvals, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing sharing, uint32_t num, uint32_t *hidden3_2){

	/**
		Create the ABYParty object which defines the basis of all the
		 	 operations which are happening.Operations performed are on the
		 	 basis of the role played by this object.
	*/

	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads,
			mt_alg, 15'000'000);

	/**
		Get to know all the sharing types available in the program.
	*/

	vector<Sharing*>& sharings = party->GetSharings();

	/**
		Create the circuit object on the basis of the sharing type
			being inputed.
	*/

	ArithmeticCircuit* circ = (ArithmeticCircuit*) sharings[sharing]->GetCircuitBuildRoutine();

	share *s_hidden3_2, *s_out;

	nvals = 10;

	s_hidden3_2 = circ->PutSharedSIMDINGate(nvals, hidden3_2, bitlen);
	
	s_out = circ->PutOUTGate(s_hidden3_2, ALL);

	party->ExecCircuit();

	uint32_t out_bitlen, out_nvals, *out_vals;
	s_out->get_clear_value_vec(&out_vals, &out_bitlen, &out_nvals);

	
	int32_t *result;
	result = new int32_t[nvals];
	for(int i = 0; i < nvals; i++){
		result[i] = out_vals[i];
	}


	/* writing in csv file */
	
	ofstream outputfile("./output[0].csv");
	for(int i = 0; i < nvals; i++){
		outputfile << result[i] << "\n";
	}

	outputfile.close();

	delete party;

	return 0;

}


/* Full connection function */
share* Fullconnection(share *s_x, share *s_y, int num, int col, int row, int bitlen, 
	ArithmeticCircuit *ac, uint32_t *posids, uint32_t *posids_index){

	int mod = 0, zero = 0;
	int ind=0;

	share *s_a, *s_b, *s_c, *s_out;

	uint32_t *posW;
	posW = new uint32_t[row];

	s_out = ac->PutSIMDCONSGate(col, zero, bitlen);
	s_out = ac->PutSplitterGate(s_out); //output matrix

	for(int i=0; i<col; i++){
		uint32_t *subposids;
		subposids = new uint32_t[posids_index[i]];

		for(int x = 0; x < posids_index[i]; x++){
			subposids[x] = posids[ind+x];			
		}

		ind = ind + posids_index[i];

		for(int index=0; index<row; index++){
			posW[index] = i*row+index;
		}
		s_a = ac->PutSubsetGate(s_x, posW, row);		
		s_a = ac->PutSubsetGate(s_a, subposids, posids_index[i]);		
		s_b = ac->PutSubsetGate(s_y, subposids, posids_index[i]);

		s_c = ac->PutMULGate(s_a, s_b);
		s_c = ac->PutSplitterGate(s_c);

		for(int j=0; j<posids_index[i]; j++){
			s_out->set_wire_id(i, ac->PutADDGate(s_out->get_wire_id(i), s_c->get_wire_id(j)));
		}
		s_c = ac->PutCombinerGate(s_c);
		delete[] subposids;
	}

	//create SIMD share from non-SIMD share	
	s_out = ac->PutCombinerGate(s_out);

	delete s_a;
	delete s_b;
	delete s_c;
	delete[] posW;

	return s_out;
}


/* Batchnormalization function */
share* BatchnormAct(share *s_x, share *s_y, ArithmeticCircuit *ac){
	
	share *s_out;

	s_out = ac->PutADDGate(s_x, s_y);
	
	delete s_x;
	delete s_y;

	return s_out;
}

share* Batchnorm(share *s_x, share *s_y, share *s_t, ArithmeticCircuit *ac){
	
	share *s_out;

	s_x = ac->PutMULGate(s_x, s_y);
	s_out = ac->PutADDGate(s_x, s_t);
	
	delete s_x;
	delete s_y;
	delete s_t;

	return s_out;
}

/* Activation function */
share* Activation(share *s_x, int num, int bitlen, ArithmeticCircuit *ac, BooleanCircuit *bc, BooleanCircuit *yc){

	int two = 2, sign = 2147483647, one = 1;

	share *s_two, *s_sign, *s_one, *s_val;
	
	s_two = ac->PutSIMDCONSGate(num, two, bitlen);
	s_sign = yc->PutSIMDCONSGate(num, sign, bitlen);
	s_one = ac->PutSIMDCONSGate(num, one, bitlen);
	
	/* Aritnmetic -> Yao */
	s_x = yc -> PutA2YGate(s_x);

	s_val = yc->PutGTGate(s_sign, s_x);

	/* Yao -> Boolean -> Arithmetic */
	s_val = bc -> PutY2BGate(s_val);
	s_val = ac->PutB2AGate(s_val);

	share *s_e, *s_out;
	
	/* 2*s_val-1 */	
	s_e = ac->PutMULGate(s_val, s_two);
	s_out = ac->PutSUBGate(s_e, s_one);
	
	delete s_x;
	delete s_two;
	delete s_sign;
	delete s_one;
	delete s_val;
	delete s_e;

	return s_out;

}




