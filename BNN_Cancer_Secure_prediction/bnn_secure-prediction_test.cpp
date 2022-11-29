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
					"Number of nodes of hidden layer, default: 2", false, false }, {
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
	uint32_t bitlen = 32, nvals = 2, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;

	read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address,
			&port, &test_op);
	
	uint32_t N = nvals;	//Number of nodes of hidden layer, default: 2

	seclvl seclvl = get_sec_lvl(secparam);

	/* Circuit to make shares */
	
	ABYParty* party = new ABYParty(role, (char*)address.c_str(), port, seclvl, bitlen, nthreads, mt_alg);

	vector<Sharing*>& sharings = party->GetSharings();

	ArithmeticCircuit* circ = (ArithmeticCircuit*) sharings[S_ARITH]->GetCircuitBuildRoutine();

	/* share in the first layer */

	share *s_W1, *s_input, *s_fullconnection, *s_middlefull, 
		*s_s1, *s_t1;

	/* the step to make share using in the first layer */

	/* convert W1.csv into array W1[] */
	uint32_t *W1;
	uint32_t W1_num = 90*N;
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
	input = new uint32_t[90];
	uint32_t input_flen;
	uint32_t input_col = 0;
	uint32_t input_row = 0;
	string input_fname = "./param/input[0].csv";
	input_flen = fileread(input, input_fname, &input_col, &input_row, 90); 

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

	/* make the pre-shared inputs to use in another circuit */

	/* the first layer */
	s_W1 = circ->PutSharedOUTGate(s_W1);
	s_input = circ->PutSharedOUTGate(s_input);
	s_fullconnection = circ->PutSharedOUTGate(s_fullconnection);
	s_middlefull = circ->PutSharedOUTGate(s_middlefull);
	s_s1 = circ->PutSharedOUTGate(s_s1);
	s_t1 = circ->PutSharedOUTGate(s_t1);
	
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

	delete party;

	uint32_t *hidden1_2;

	/* execute SecureBNN_ABY */

	hidden1_2 = BNN_Cancer_Secure_prediction(role, (char*) address.c_str(), port, seclvl, 1, 32,
			nthreads, mt_alg, S_ARITH, nvals,
			out_W1, out_W1nvals, out_input, out_inputnvals,
			out_fullconnection, out_fullconnectionnvals,
			out_middlefull, out_middlefullnvals,
			out_s1, out_s1nvals, out_t1, out_t1nvals, N);

	
	/* decrypt hidden1_2 and convert decrypted hidden3_2 into output.csv */

	Enc_circuit(role, (char*) address.c_str(), port, seclvl, 1, 32,
			nthreads, mt_alg, S_ARITH, nvals, hidden1_2);


	return 0;

}
