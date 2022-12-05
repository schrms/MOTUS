//Utility libs
#include "../ABY/src/abycore/ENCRYPTO_utils/crypto/crypto.h"
#include "../ABY/src/abycore/ENCRYPTO_utils/parse_options.h"
//ABY Party class
#include "../ABY/src/abycore/aby/abyparty.h"
#include "common/bnn_secure-prediction.h"
#include <iostream>
#include <sstream>
#include <string>
using namespace std;

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role,
		uint32_t* bitlen, uint32_t* nvals, uint32_t* secparam, string* address,
		uint16_t* port, int32_t* test_op) {

	uint32_t int_role = 0, int_port = 0;
	bool useffc = false;

	parsing_ctx options[] =
			{ { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false }, {
					(void*) nvals, T_NUM, "n",
					"Number of parallel operation elements", false, false }, {
					(void*) bitlen, T_NUM, "b", "Bit-length, default 32", false,
					false }, { (void*) secparam, T_NUM, "s",
					"Symmetric Security Bits, default: 128", false, false }, {
					(void*) address, T_STR, "a",
					"IP-address, default: localhost", false, false }, {
					(void*) &int_port, T_NUM, "p", "Port, default: 7766", false,
					false }, { (void*) test_op, T_NUM, "t",
					"Single test (leave out for all operations), default: off",
					false, false } };

	if (!parse_options(argcp, argvp, options,
			sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		cout << "Exiting" << endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	//delete options;

	return 1;
}

/* function of reading CSVfile */

uint32_t fileread(uint32_t test[], string fname, uint32_t *col, uint32_t *row, uint32_t num){
	ifstream fin(fname);
	string str;

	if(!fin){
		exit(0);
	}

	uint32_t i = 0;
	uint32_t colnum = 0;
	uint32_t rownum = 0;

	while(getline(fin, str)){
		if(num == i){
			break;
		}else{
			string tmp = "";
			istringstream stream(str);
			rownum = 0;
			while(getline(stream, tmp, ',')){
				test[i] = stoi(tmp);
				i++;
				rownum++;
			}
			colnum++;
		}
	}

	*col = colnum;
	*row = rownum;

	fin.close();

	return i;
}

int main(int argc, char** argv) {

	e_role role;
	uint32_t bitlen = 32, nvals = 128, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;

	read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address,
			&port, &test_op);

	seclvl seclvl = get_sec_lvl(secparam);

	/* Circuit to make shares */
	
	ABYParty* party = new ABYParty(role, (char*)address.c_str(), port, seclvl, bitlen, nthreads, mt_alg);

	vector<Sharing*>& sharings = party->GetSharings();

	ArithmeticCircuit* circ = (ArithmeticCircuit*) sharings[S_ARITH]->GetCircuitBuildRoutine();

	/* share in the first layer */

	share *s_W1, *s_input, *s_u1;
	 	
	/* share in the second layer */

	share *s_W2, *s_u2;

	/* share in the third layer */
	//share *s_W3, *s_u3;

	/* share in the forth layer */
	share *s_W3, *s_s3, *s_t3;

	/* the step to make share using in the first layer */

	/* convert W1.csv into array W1[] */
	uint32_t *W1;
	uint32_t W1_num = 5*5*5;
	W1 = new uint32_t[W1_num];
	uint32_t W1_flen; //length of W1
	uint32_t W1_col = 0; //col of matrix
	uint32_t W1_row = 0; //row of matrix
	string W1_fname = "./param/W1.csv"; //file path of W1.csv
	W1_flen = fileread(W1, W1_fname, &W1_col, &W1_row, W1_num); //read W1.csv
	
	/* Setting nvals and bitlen */

	nvals = W1_num;
	bitlen = 32;

	/* make sparse index */

	uint32_t *W1_temp;
	W1_temp = new uint32_t[W1_num];

	uint32_t *W1posids_index;
	W1posids_index = new uint32_t[5];
	int index_W1 = 0;
	int size_W1 = 0;

	for(int i=0; i<5; i++){
		for(int j=0; j<25; j++){
			if(W1[i*25+j] != 0){
				W1_temp[size_W1] = j;
				size_W1++;
				index_W1++;
			}
		}
		W1posids_index[i] = index_W1;
		index_W1=0;
	}

	uint32_t *posids_W1;
	posids_W1 = new uint32_t[size_W1];

	for(int i=0; i<size_W1; i++){
		posids_W1[i] = W1_temp[i];
	}

	delete[] W1_temp;

	/* convert input[0].csv into array input[] */
	uint32_t *input;
	input = new uint32_t[784];
	uint32_t input_flen;
	uint32_t input_col = 0;
	uint32_t input_row = 0;
	string input_fname = "./param/input[0].csv";
	input_flen = fileread(input, input_fname, &input_col, &input_row, 784); 

	/* make the share in Convolution*/

	if(role == SERVER) { 
		s_W1 = circ->PutSIMDINGate(nvals, W1, bitlen, SERVER);
		s_input = circ->PutDummySIMDINGate(784, bitlen);
	} else { //role == CLIENT
		s_W1 = circ->PutDummySIMDINGate(nvals, bitlen);
		s_input = circ->PutSIMDINGate(784, input, bitlen, CLIENT);
	}

	/* convert u1.csv into u1[] */
	uint32_t *u1;
	u1 = new uint32_t[24*24*5];

	uint32_t *u1_temp;
	u1_temp = new uint32_t[5];
	uint32_t u1_flen;
	uint32_t u1_col = 0;
	uint32_t u1_row = 0;
	string u1_fname = "./param/u1.csv";
	u1_flen = fileread(u1_temp, u1_fname, &u1_col, &u1_row, 5); 

	for(int i=0; i<5; i++){
		for(int j=24*24*i; j<24*24*(i+1); j++){
			u1[j] = u1_temp[i];
		}
	}

	/* make the share in Batchnormalization*/

	if(role == SERVER) { 
		s_u1 = circ->PutSIMDINGate(24*24*5, u1, bitlen, SERVER);
	} else { //role == CLIENT
		s_u1 = circ->PutDummySIMDINGate(24*24*5, bitlen);
	}

	/* the step to make share using in the second layer */

	/* the second layer */

	/* convert W3.csv into W3[] */
	uint32_t *W2;
	uint32_t W2_num = 24*24*5*100;
	W2 = new uint32_t[W2_num];
	uint32_t W2_flen; 
	uint32_t W2_col = 0; 
	uint32_t W2_row = 0; 
	string W2_fname = "./param/W2.csv"; //file path of W3.csv
	W2_flen = fileread(W2, W2_fname, &W2_col, &W2_row, W2_num); //read W3.csv

	/* Setting nvals and bitlen */

	nvals = W2_num;
	bitlen = 32;

		/* make sparse index */

	uint32_t *W2_temp;
	W2_temp = new uint32_t[W2_num];

	uint32_t *W2posids_index;
	W2posids_index = new uint32_t[100];
	int index_W2 = 0;
	int size_W2 = 0;

	for(int i=0; i<100; i++){
		for(int j=0; j<24*24*5; j++){
			if(W2[i*24*24*5+j] != 0){
				W2_temp[size_W2] = j;
				size_W2++;
				index_W2++;
			}
		}
		W2posids_index[i] = index_W2;
		index_W2=0;
	}

	uint32_t *posids_W2;
	posids_W2 = new uint32_t[size_W2];

	for(int i=0; i<size_W2; i++){
		posids_W2[i] =W2_temp[i];
	}

	delete[] W2_temp;

	/* make the share in Convolution */

	if(role == SERVER) { 
		s_W2 = circ->PutSIMDINGate(nvals, W2, bitlen, SERVER);
	} else { //role == CLIENT
		s_W2 = circ->PutDummySIMDINGate(nvals, bitlen);
	}

	/* convert u3.csv into u3[] */

	uint32_t *u2;
	u2 = new uint32_t[100];
	uint32_t u2_flen;
	uint32_t u2_col = 0;
	uint32_t u2_row = 0;
	string u2_fname = "./param/u2.csv";
	u2_flen = fileread(u2, u2_fname, &u2_col, &u2_row, 100); 

	nvals = 100;

	/* make the share in Batchnormalization */

	if(role == SERVER) { 
		s_u2 = circ->PutSIMDINGate(nvals, u2, bitlen, SERVER);
	} else { //role == CLIENT
		s_u2 = circ->PutDummySIMDINGate(nvals, bitlen);
	}

	/* The forth layer */

	/* convert W4.csv into W4[] */
	uint32_t *W3;
	uint32_t W3_num = 10*100;
	W3 = new uint32_t[W3_num];
	uint32_t W3_flen; 
	uint32_t W3_col = 0; 
	uint32_t W3_row = 0; 
	string W3_fname = "./param/W3.csv"; //file path of W4.csv
	W3_flen = fileread(W3, W3_fname, &W3_col, &W3_row, W3_num); //read W4.csv

	/* Setting nvals and bitlen */

	nvals = W3_num;
	bitlen = 32;

		/* make sparse index */

	uint32_t *W3_temp;
	W3_temp = new uint32_t[W3_num];

	uint32_t *W3posids_index;
	W3posids_index = new uint32_t[10];
	int index_W3 = 0;
	int size_W3 = 0;

	for(int i=0; i<10; i++){
		for(int j=0; j<100; j++){
			if(W3[i*100+j] != 0){
				W3_temp[size_W3] = j;
				size_W3++;
				index_W3++;
			}
		}
		W3posids_index[i] = index_W3;
		index_W3 = 0;
	}

	uint32_t *posids_W3;
	posids_W3 = new uint32_t[size_W3];

	for(int i=0; i<size_W3; i++){
		posids_W3[i] =W3_temp[i];
	}

	delete[] W3_temp;

	/* make the share in Fullconnection */

	if(role == SERVER) { 
		s_W3 = circ->PutSIMDINGate(nvals, W3, bitlen, SERVER);
	} else { //role == CLIENT
		s_W3 = circ->PutDummySIMDINGate(nvals, bitlen);
	}

	/* convert s4.csv into s4[] */
	uint32_t *s3;
	s3 = new uint32_t[10];
	uint32_t s3_flen;
	uint32_t s3_col = 0;
	uint32_t s3_row = 0;
	string s3_fname = "./param/s3.csv";
	s3_flen = fileread(s3, s3_fname, &s3_col, &s3_row, 10); 

	/* convert t4.csv into t4[]*/
	uint32_t *t3;
	t3 = new uint32_t[10];
	uint32_t t3_flen;
	uint32_t t3_col = 0;
	uint32_t t3_row = 0;
	string t3_fname = "./param/t3.csv";
	t3_flen = fileread(t3, t3_fname, &t3_col, &t3_row, 10);

	nvals = 10; 

	/* make the share in Batchnormalization */

	if(role == SERVER) { 
		s_s3 = circ->PutSIMDINGate(nvals, s3, bitlen, SERVER);
		s_t3 = circ->PutSIMDINGate(nvals, t3, bitlen, SERVER);
	} else { //role == CLIENT
		s_s3 = circ->PutDummySIMDINGate(nvals, bitlen);
		s_t3 = circ->PutDummySIMDINGate(nvals, bitlen);
	}

	/* make the pre-shared inputs to use in another circuit */

	/* the first layer */
	s_W1 = circ->PutSharedOUTGate(s_W1);
	s_input = circ->PutSharedOUTGate(s_input);
	s_u1 = circ->PutSharedOUTGate(s_u1);
	
	/* the second layer */
	s_W2 = circ->PutSharedOUTGate(s_W2);
	s_u2 = circ->PutSharedOUTGate(s_u2);

	/* the third layer */
	//s_W3 = circ->PutSharedOUTGate(s_W3);
	//s_u3 = circ->PutSharedOUTGate(s_u3);

	/* the forth layer */
	s_W3 = circ->PutSharedOUTGate(s_W3);
	s_s3 = circ->PutSharedOUTGate(s_s3);
	s_t3 = circ->PutSharedOUTGate(s_t3);

	/**
	 Executing the circuit using the ABYParty object evaluate the problem.
	 */

	party->ExecCircuit();


	/**
	 Get vector output.
	 */


	uint32_t out_W1bitlen, out_W1nvals, *out_W1;
	s_W1->get_clear_value_vec(&out_W1, &out_W1bitlen, &out_W1nvals);

	uint32_t out_inputbitlen, out_inputnvals, *out_input;
	s_input->get_clear_value_vec(&out_input, &out_inputbitlen, &out_inputnvals);

	uint32_t out_u1bitlen, out_u1nvals, *out_u1;
	s_u1->get_clear_value_vec(&out_u1, &out_u1bitlen, &out_u1nvals);

	uint32_t out_W2bitlen, out_W2nvals, *out_W2;
	s_W2->get_clear_value_vec(&out_W2, &out_W2bitlen, &out_W2nvals);

	uint32_t out_u2bitlen, out_u2nvals, *out_u2;
	s_u2->get_clear_value_vec(&out_u2, &out_u2bitlen, &out_u2nvals);

	/*uint32_t out_W3bitlen, out_W3nvals, *out_W3;
	s_W3->get_clear_value_vec(&out_W3, &out_W3bitlen, &out_W3nvals);

	uint32_t out_u3bitlen, out_u3nvals, *out_u3;
	s_u3->get_clear_value_vec(&out_u3, &out_u3bitlen, &out_u3nvals);*/

	uint32_t out_W3bitlen, out_W3nvals, *out_W3;
	s_W3->get_clear_value_vec(&out_W3, &out_W3bitlen, &out_W3nvals);

	uint32_t out_s3bitlen, out_s3nvals, *out_s3;
	s_s3->get_clear_value_vec(&out_s3, &out_s3bitlen, &out_s3nvals);

	uint32_t out_t3bitlen, out_t3nvals, *out_t3;
	s_t3->get_clear_value_vec(&out_t3, &out_t3bitlen, &out_t3nvals);

	delete party;

	uint32_t *hidden3_2;

	/* execute SecureBNN_ABY */

	hidden3_2 = BNN_Mnist_Secure_prediction(role, (char*) address.c_str(), port, seclvl, 1, 32,
			nthreads, mt_alg, S_ARITH, nvals,
			out_W1, out_W1nvals, out_input, out_inputnvals, out_u1, out_u1nvals,  

			out_W2, out_W2nvals, out_u2, out_u2nvals,  

			out_W3, out_W3nvals, out_s3, out_s3nvals, out_t3, out_t3nvals, 

			posids_W1, posids_W2, posids_W3, 
			W1posids_index, W2posids_index, W3posids_index);

	/* decrypt hidden5_2 and convert decrypted hidden5_2 into output.csv */

	Enc_circuit(role, (char*) address.c_str(), port, seclvl, 1, 32,
			nthreads, mt_alg, S_ARITH, nvals, hidden3_2);


	return 0;

}
