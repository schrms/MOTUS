#include "bnn_secure-prediction.h"
#include <iostream>
#include <sstream>
#include <string>
using namespace std;


/* Secure_prediction */
uint32_t* BNN_Cancer_Secure_prediction(e_role role, char* address, uint16_t port, seclvl seclvl,
		uint32_t nvals, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing sharing, uint32_t num,
		uint32_t *W1, uint32_t W1nvals, uint32_t *input, uint32_t inputnvals,
		uint32_t *fullconnection, uint32_t fullconnectionnvals,
		uint32_t *middlefull, uint32_t middlefullnvals,
		uint32_t *s1, uint32_t s1nvals, uint32_t *t1, uint32_t t1nvals, uint32_t N) {

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

	/**
		Creating the share objects used in SecureBNN_ABY
	*/

	share *s_W1, *s_input, *s_fullconnection, *s_middlefull, *s_hidden1_1,
	 *s_s1, *s_t1, *s_hidden1_2, *s_out;

	s_W1 = circ->PutSharedSIMDINGate(W1nvals, W1, bitlen);
	s_input = circ->PutSharedSIMDINGate(inputnvals, input, bitlen);
	s_fullconnection = circ->PutSharedSIMDINGate(fullconnectionnvals, fullconnection, bitlen);
	s_middlefull = circ->PutSharedSIMDINGate(middlefullnvals, middlefull, bitlen);
	s_s1 = circ->PutSharedSIMDINGate(s1nvals, s1, bitlen);
	s_t1 = circ->PutSharedSIMDINGate(t1nvals, t1, bitlen);
	
	/* secret computation (Fullconnection)*/

	s_hidden1_1 = Fullconnection(s_W1, s_input, s_fullconnection, s_middlefull, 90*N, N, 90, (ArithmeticCircuit*) circ);

	/* change value of nvals */
	nvals = N;
	
	/* secret computation (Batchnormalization)*/

	s_hidden1_2 = Batchnorm(s_hidden1_1, s_s1, s_t1, (ArithmeticCircuit*) circ);

	/* make the pre-shared inputs to use in another circuit */	
	s_out = circ->PutSharedOUTGate(s_hidden1_2);

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
		e_sharing sharing, uint32_t num, uint32_t *hidden1_2){

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

	share *s_hidden1_2, *s_out;

	nvals = 2;

	s_hidden1_2 = circ->PutSharedSIMDINGate(nvals, hidden1_2, bitlen);
	
	s_out = circ->PutOUTGate(s_hidden1_2, ALL);

	party->ExecCircuit();

	uint32_t out_bitlen, out_nvals, *out_vals;
	s_out->get_clear_value_vec(&out_vals, &out_bitlen, &out_nvals);

	
	int32_t *result;
	result = new int32_t[nvals];
	for(int i = 0; i < nvals; i++){
		result[i] = out_vals[i];
	}
	

	/* writing in csv file */

	ofstream outputfile("./param/output[0].csv");
	for(int i = 0; i < nvals; i++){
		outputfile << result[i] << "\n";
	}

	outputfile.close();

	delete party;

	return 0;

}



/* Full connection function */
share* Fullconnection(share *s_x, share *s_y, share *s_m, share *s_e, uint32_t num, uint32_t col, uint32_t row, ArithmeticCircuit *ac){
	int mod = 0;

	// split SIMD gate to separate wires (size many)
	s_x = ac->PutSplitterGate(s_x);
	s_y = ac->PutSplitterGate(s_y);
	s_e = ac->PutSplitterGate(s_e); //extra matrix
	s_m = ac->PutSplitterGate(s_m); //output matrix

	for (int j = 0; j < num; j = j + row) {
		for (int i = 0; i < row; i++) {
			s_e->set_wire_id((i+j), ac->PutMULGate(s_x->get_wire_id(i+j), s_y->get_wire_id(i)));
		}
	}

	for (int k = 0; k < num; k++) {
		if ((k != 0) && (k % row == 0)){
			mod = mod + 1;
		}
		s_m->set_wire_id(mod, ac->PutADDGate(s_m->get_wire_id(mod), s_e->get_wire_id(k)));
	}
	
	//create SIMD share from non-SIMD share	
	s_m = ac->PutCombinerGate(s_m);
	return s_m;
}


/* Batchnormalization function */
share* Batchnorm(share *s_x, share *s_y, share *s_t, ArithmeticCircuit *ac){
	
	share *s_out;

	s_x = ac->PutMULGate(s_x, s_y);
	s_out = ac->PutADDGate(s_x, s_t);

	return s_out;
}

/* Activation function */
share* Activation(share *s_x, share *s_p, share *s_n, ArithmeticCircuit *ac){

	share *s_e, *s_out;
		
	s_e = ac->PutMULGate(s_x, s_n);
	s_out = ac->PutSUBGate(s_e, s_p);
	
	return s_out;

}


