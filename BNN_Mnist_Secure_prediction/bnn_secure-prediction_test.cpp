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
					"Number of nodes of hidden layer, default: 128", false, false }, {
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
	
	uint32_t N = nvals;	//Number of nodes of hidden layer, default: 128


	seclvl seclvl = get_sec_lvl(secparam);

	/* Circuit to make shares */
	
	ABYParty* party = new ABYParty(role, (char*)address.c_str(), port, seclvl, bitlen, nthreads, mt_alg);

	vector<Sharing*>& sharings = party->GetSharings();

	ArithmeticCircuit* circ = (ArithmeticCircuit*) sharings[S_ARITH]->GetCircuitBuildRoutine();

	/* share in the first layer */

	share *s_W1, *s_input, *s_fullconnection, *s_middlefull, 
		*s_s1, *s_t1,
	 	*s_act, *s_sign, *s_pos;

	/* share in the second layer */

	share *s_W2, *s_fullconnection1, *s_middlefull1,
	 	*s_s2, *s_t2;

	/* share in the third layer */
	share *s_W3, *s_fullconnection2, *s_middlefull2, 
	 	*s_s3, *s_t3;

	/* the step to make share using in the first layer */

	/* convert W1.csv into array W1[] */
	uint32_t *W1;
	uint32_t W1_num = 784*N;
	W1 = new uint32_t[W1_num];
	uint32_t W1_flen; //length of W1
	uint32_t W1_col = 0; //col of matrix
	uint32_t W1_row = 0; //row of matrix
	string W1_fname = "./param/W1.csv"; //file path of W1.csv
	W1_flen = fileread(W1, W1_fname, &W1_col, &W1_row, W1_num); //read W1.csv
	

	/* Setting nvals and bitlen */

	nvals = W1_flen;
	bitlen = 32;

	/* convert input[0].csv into array input[] */
	uint32_t *input;
	input = new uint32_t[784];
	uint32_t input_flen;
	uint32_t input_col = 0;
	uint32_t input_row = 0;
	string input_fname = "./param/input[0].csv";
	input_flen = fileread(input, input_fname, &input_col, &input_row, 784); 

	/* make temporary array required in Fullconnection */
	uint32_t fullconnection = 0;
	s_fullconnection = circ->PutSIMDCONSGate(W1_col, fullconnection, bitlen);

	/* make temporary array required in Fullconnection */
	uint32_t middlefull = 0;
	s_middlefull = circ->PutSIMDCONSGate(nvals, middlefull, bitlen);

	/* make the share in Fullconnection*/

	if(role == SERVER) { 
		s_W1 = circ->PutSIMDINGate(nvals, W1, bitlen, SERVER);
		s_input = circ->PutDummySIMDINGate(input_col, bitlen);
	} else { //role == CLIENT
		s_W1 = circ->PutDummySIMDINGate(nvals, bitlen);
		s_input = circ->PutSIMDINGate(input_col, input, bitlen, CLIENT);
	}

	/* change value of nvals */
	nvals = W1_col;

	/* convert s1.csv into s1[] */
	uint32_t *s1;
	s1 = new uint32_t[N];
	uint32_t s1_flen;
	uint32_t s1_col = 0;
	uint32_t s1_row = 0;
	string s1_fname = "./param/s1.csv";
	s1_flen = fileread(s1, s1_fname, &s1_col, &s1_row, N); 


	/* convert t1.csv into t1[] */
	uint32_t *t1;
	t1 = new uint32_t[N];
	uint32_t t1_flen;
	uint32_t t1_col = 0;
	uint32_t t1_row = 0;
	string t1_fname = "./param/t1.csv";
	t1_flen = fileread(t1, t1_fname, &t1_col, &t1_row, N); 

	/* make the share in Batchnormalization*/

	if(role == SERVER) { 
		s_s1 = circ->PutSIMDINGate(W1_col, s1, bitlen, SERVER);
		s_t1 = circ->PutSIMDINGate(W1_col, t1, bitlen, SERVER);
	} else { //role == CLIENT
		s_s1 = circ->PutDummySIMDINGate(W1_col, bitlen);
		s_t1 = circ->PutDummySIMDINGate(W1_col, bitlen);
	}

	
	/* make the array required in Activation */
	uint32_t act = 2;
	s_act = circ->PutSIMDCONSGate(nvals, act, bitlen);

	/* make the array required in Activation */
	uint32_t sign = 2147483647;
	s_sign = circ->PutSIMDCONSGate(nvals, sign, bitlen);

	/* make the array required in Activation */
	uint32_t pos = 1;
	s_pos = circ->PutSIMDCONSGate(nvals, pos, bitlen);


	/* the step to make share using in the second and third layer */

	/* the second layer */

	/* convert W2.csv into W2[] */

	uint32_t *cW2;
	uint32_t cW2_num = 1000*N;
	cW2 = new uint32_t[cW2_num];
	uint32_t cW2_flen; //length of W
	uint32_t cW2_col = 0; //col of matrix
	uint32_t cW2_row = 0; //row of matrix
	string cW2_fname = "./param/W2.csv"; //file path of W2.csv
	cW2_flen = fileread(cW2, cW2_fname, &cW2_col, &cW2_row, cW2_num); //read W2.csv

	uint32_t *W2;
	uint32_t W2_num = N*N;
	W2 = new uint32_t[W2_num];
	
	for(int j=0; j<N; j++){
		for(int i=0; i<N; i++){
			W2[j*N+i] = cW2[j*1000+i];
		}
	}

	uint32_t W2_flen = N*N; //length of W
	uint32_t W2_col = N; //col of matrix
	uint32_t W2_row = N; //row of matrix

		

	/* Setting nvals and bitlen */

	nvals = W2_flen;
	bitlen = 32;
	
	/* make temporary array required in Fullconnection */
	uint32_t fullconnection1 = 0;
	s_fullconnection1 = circ->PutSIMDCONSGate(W2_col, fullconnection1, bitlen);

	/* make temporary array required in Fullconnection */
	uint32_t middlefull1 = 0;
	s_middlefull1 = circ->PutSIMDCONSGate(nvals, middlefull1, bitlen);
	

	/* make the share in Fullconnection*/

	if(role == SERVER) { 
		s_W2 = circ->PutSIMDINGate(nvals, W2, bitlen, SERVER);
	} else { //role == CLIENT
		s_W2 = circ->PutDummySIMDINGate(nvals, bitlen);
	}

	/* change value of nvals */
	nvals = W2_col;

	/* convert s2.csv into s2[] */
	uint32_t *s2;
	s2 = new uint32_t[N];
	uint32_t s2_flen;
	uint32_t s2_col = 0;
	uint32_t s2_row = 0;
	string s2_fname = "./param/s2.csv";
	s2_flen = fileread(s2, s2_fname, &s2_col, &s2_row, N); 

	/* convert t2.csv into t2[]*/
	uint32_t *t2;
	t2 = new uint32_t[N];
	uint32_t t2_flen;
	uint32_t t2_col = 0;
	uint32_t t2_row = 0;
	string t2_fname = "./param/t2.csv";
	t2_flen = fileread(t2, t2_fname, &t2_col, &t2_row, N); 

	/* make the share in Batchnormalization */

	if(role == SERVER) { 
		s_s2 = circ->PutSIMDINGate(W2_col, s2, bitlen, SERVER);
		s_t2 = circ->PutSIMDINGate(W2_col, t2, bitlen, SERVER);
	} else { //role == CLIENT
		s_s2 = circ->PutDummySIMDINGate(W2_col, bitlen);
		s_t2 = circ->PutDummySIMDINGate(W2_col, bitlen);
	}

	/* The third layer */

	/* convert W3.csv into W3[] */
	uint32_t *cW3;
	uint32_t cW3_num = 10000;
	cW3 = new uint32_t[cW3_num];
	uint32_t cW3_flen; 
	uint32_t cW3_col = 0; 
	uint32_t cW3_row = 0; 
	string cW3_fname = "./param/W3.csv"; //file path of W3.csv
	cW3_flen = fileread(cW3, cW3_fname, &cW3_col, &cW3_row, cW3_num); //read W3.csv

	uint32_t *W3;
	uint32_t W3_num = 10*N;
	W3 = new uint32_t[W3_num];
	
	for(int j=0; j<10; j++){
		for(int i=0; i<N; i++){
			W3[j*N+i] = cW3[j*1000+i];
		}
	}

	uint32_t W3_flen = 10*N; //length of W3
	uint32_t W3_col = 10; //col of matrix
	uint32_t W3_row = N; //row of matrix


	/* Setting nvals and bitlen */

	nvals = W3_flen;
	bitlen = 32;
	
	/* make temporary array required in Fullconnection */
	uint32_t fullconnection2 = 0;
	s_fullconnection2 = circ->PutSIMDCONSGate(W3_col, fullconnection2, bitlen);

	/* make temporary array required in Fullconnection */
	uint32_t middlefull2 = 0;
	s_middlefull2 = circ->PutSIMDCONSGate(nvals, middlefull2, bitlen);

	/* make the share in Fullconnection */

	if(role == SERVER) { 
		s_W3 = circ->PutSIMDINGate(nvals, W3, bitlen, SERVER);
	} else { //role == CLIENT
		s_W3 = circ->PutDummySIMDINGate(nvals, bitlen);
	}

	/* change value of nvals */
	nvals = W3_col;

	/* convert s3.csv into s3[] */
	uint32_t *s3;
	s3 = new uint32_t[10];
	uint32_t s3_flen;
	uint32_t s3_col = 0;
	uint32_t s3_row = 0;
	string s3_fname = "./param/s3.csv";
	s3_flen = fileread(s3, s3_fname, &s3_col, &s3_row, 10); 

	/* convert t3.csv into t3[] */
	uint32_t *t3;
	t3 = new uint32_t[10];
	uint32_t t3_flen;
	uint32_t t3_col = 0;
	uint32_t t3_row = 0;
	string t3_fname = "./param/t3.csv";
	t3_flen = fileread(t3, t3_fname, &t3_col, &t3_row, 10); 


	/* make the share in Batchnormalization */

	if(role == SERVER) { 
		s_s3 = circ->PutSIMDINGate(W3_col, s3, bitlen, SERVER);
		s_t3 = circ->PutSIMDINGate(W3_col, t3, bitlen, SERVER);
	} else { //role == CLIENT
		s_s3 = circ->PutDummySIMDINGate(W3_col, bitlen);
		s_t3 = circ->PutDummySIMDINGate(W3_col, bitlen);
	}

	/* make the pre-shared inputs to use in another circuit */

	/* the first layer */
	s_W1 = circ->PutSharedOUTGate(s_W1);
	s_input = circ->PutSharedOUTGate(s_input);
	s_fullconnection = circ->PutSharedOUTGate(s_fullconnection);
	s_middlefull = circ->PutSharedOUTGate(s_middlefull);
	s_s1 = circ->PutSharedOUTGate(s_s1);
	s_t1 = circ->PutSharedOUTGate(s_t1);
	s_act = circ->PutSharedOUTGate(s_act);
	s_sign = circ->PutSharedOUTGate(s_sign);
	s_pos = circ->PutSharedOUTGate(s_pos);

	/* the second layer */
	s_W2 = circ->PutSharedOUTGate(s_W2);
	s_fullconnection1 = circ->PutSharedOUTGate(s_fullconnection1);
	s_middlefull1 = circ->PutSharedOUTGate(s_middlefull1);
	s_s2 = circ->PutSharedOUTGate(s_s2);
	s_t2 = circ->PutSharedOUTGate(s_t2);

	/* the third layer */
	s_W3 = circ->PutSharedOUTGate(s_W3);
	s_fullconnection2 = circ->PutSharedOUTGate(s_fullconnection2);
	s_middlefull2 = circ->PutSharedOUTGate(s_middlefull2);
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

	uint32_t out_fullconnectionbitlen, out_fullconnectionnvals, *out_fullconnection;
	s_fullconnection->get_clear_value_vec(&out_fullconnection, &out_fullconnectionbitlen, &out_fullconnectionnvals);

	uint32_t out_middlefullbitlen, out_middlefullnvals, *out_middlefull;
	s_middlefull->get_clear_value_vec(&out_middlefull, &out_middlefullbitlen, &out_middlefullnvals);

	uint32_t out_s1bitlen, out_s1nvals, *out_s1;
	s_s1->get_clear_value_vec(&out_s1, &out_s1bitlen, &out_s1nvals);

	uint32_t out_t1bitlen, out_t1nvals, *out_t1;
	s_t1->get_clear_value_vec(&out_t1, &out_t1bitlen, &out_t1nvals);

	uint32_t out_actbitlen, out_actnvals, *out_act;
	s_act->get_clear_value_vec(&out_act, &out_actbitlen, &out_actnvals);

	uint32_t out_signbitlen, out_signnvals, *out_sign;
	s_sign->get_clear_value_vec(&out_sign, &out_signbitlen, &out_signnvals);

	uint32_t out_posbitlen, out_posnvals, *out_pos;
	s_pos->get_clear_value_vec(&out_pos, &out_posbitlen, &out_posnvals);

	uint32_t out_W2bitlen, out_W2nvals, *out_W2;
	s_W2->get_clear_value_vec(&out_W2, &out_W2bitlen, &out_W2nvals);

	uint32_t out_fullconnection1bitlen, out_fullconnection1nvals, *out_fullconnection1;
	s_fullconnection1->get_clear_value_vec(&out_fullconnection1, &out_fullconnection1bitlen, &out_fullconnection1nvals);

	uint32_t out_middlefull1bitlen, out_middlefull1nvals, *out_middlefull1;
	s_middlefull1->get_clear_value_vec(&out_middlefull1, &out_middlefull1bitlen, &out_middlefull1nvals);

	uint32_t out_s2bitlen, out_s2nvals, *out_s2;
	s_s2->get_clear_value_vec(&out_s2, &out_s2bitlen, &out_s2nvals);

	uint32_t out_t2bitlen, out_t2nvals, *out_t2;
	s_t2->get_clear_value_vec(&out_t2, &out_t2bitlen, &out_t2nvals);

	uint32_t out_W3bitlen, out_W3nvals, *out_W3;
	s_W3->get_clear_value_vec(&out_W3, &out_W3bitlen, &out_W3nvals);

	uint32_t out_fullconnection2bitlen, out_fullconnection2nvals, *out_fullconnection2;
	s_fullconnection2->get_clear_value_vec(&out_fullconnection2, &out_fullconnection2bitlen, &out_fullconnection2nvals);

	uint32_t out_middlefull2bitlen, out_middlefull2nvals, *out_middlefull2;
	s_middlefull2->get_clear_value_vec(&out_middlefull2, &out_middlefull2bitlen, &out_middlefull2nvals);

	uint32_t out_s3bitlen, out_s3nvals, *out_s3;
	s_s3->get_clear_value_vec(&out_s3, &out_s3bitlen, &out_s3nvals);

	uint32_t out_t3bitlen, out_t3nvals, *out_t3;
	s_t3->get_clear_value_vec(&out_t3, &out_t3bitlen, &out_t3nvals);

	delete party;

	uint32_t *hidden3_2;

	/* execute SecureBNN_ABY */

	hidden3_2 = BNN_Mnist_Secure_prediction(role, (char*) address.c_str(), port, seclvl, 1, 32,
			nthreads, mt_alg, S_ARITH, nvals,
			out_W1, out_W1nvals, out_input, out_inputnvals,
			out_fullconnection, out_fullconnectionnvals,
			out_middlefull, out_middlefullnvals,
			out_s1, out_s1nvals, out_t1, out_t1nvals, 
			out_act, out_actnvals, out_sign, out_signnvals, out_pos, out_posnvals, 

			out_W2, out_W2nvals, 
			out_fullconnection1, out_fullconnection1nvals,
			out_middlefull1, out_middlefull1nvals,
			out_s2, out_s2nvals, out_t2, out_t2nvals, 

			out_W3, out_W3nvals, 
			out_fullconnection2, out_fullconnection2nvals,
			out_middlefull2, out_middlefull2nvals,
			out_s3, out_s3nvals, out_t3, out_t3nvals, N);

	
	/* decrypt hidden3_2 and convert decrypted hidden3_2 into output.csv */

	Enc_circuit(role, (char*) address.c_str(), port, seclvl, 1, 32,
			nthreads, mt_alg, S_ARITH, nvals, hidden3_2);


	return 0;

}
