#include "bnn_secure-prediction.h"
#include <iostream>
#include <sstream>
#include <string>
using namespace std;


/* Secure_prediction */
uint32_t* BNN_Mnist_Secure_prediction(e_role role, char* address, uint16_t port, seclvl seclvl,
		uint32_t nvals, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing sharing, uint32_t num,
		uint32_t *W1, uint32_t W1nvals, uint32_t *input, uint32_t inputnvals, uint32_t *u1, uint32_t u1nvals, 

		uint32_t *W2, uint32_t W2nvals, uint32_t *u2, uint32_t u2nvals,  

		uint32_t *W3, uint32_t W3nvals, uint32_t *s3, uint32_t s3nvals, uint32_t *t3, uint32_t t3nvals, 

		uint32_t *posids_W1, uint32_t *posids_W2, uint32_t *posids_W3,  
		uint32_t *W1posids_index, uint32_t *W2posids_index, uint32_t *W3posids_index) {

	/**
		Create the ABYParty object which defines the basis of all the
		 	 operations which are happening.	Operations performed are on the
		 	 basis of the role played by this object.
	*/

	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads,
			mt_alg, 100'000'000);

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

	s_hidden1_1 = Convolution(s_W1, s_input, 28, 28, 1, 5, 5, 1, 5, bitlen, (ArithmeticCircuit*) circ, posids_W1, W1posids_index);
	s_hidden1_2 = BatchnormAct(s_hidden1_1, s_u1, (ArithmeticCircuit*) circ);
	s_hidden1_3 = Activation(s_hidden1_2, 24*24*5, bitlen, (ArithmeticCircuit*) circ, (BooleanCircuit*) booleancirc, (BooleanCircuit*) yaocirc);
	
	/* The second layer */

	s_hidden2_1 = Fullconnection(s_W2, s_hidden1_3, 100*24*24*5, 100, 24*24*5, bitlen, (ArithmeticCircuit*) circ, posids_W2, W2posids_index);
	s_hidden2_2 = BatchnormAct(s_hidden2_1, s_u2, (ArithmeticCircuit*) circ);
	s_hidden2_3 = Activation(s_hidden2_2, 100, bitlen, (ArithmeticCircuit*) circ, (BooleanCircuit*) booleancirc, (BooleanCircuit*) yaocirc);
	
	/* The forth layer*/
	s_hidden3_1 = Fullconnection(s_W3, s_hidden2_3, 10*100, 10, 100, bitlen, (ArithmeticCircuit*) circ, posids_W3, W3posids_index);
	s_hidden3_2 = Batchnorm(s_hidden3_1, s_s3, s_t3, (ArithmeticCircuit*) circ);
	
	/* make the pre-shared inputs to use in another circuit */	
	s_out = circ->PutSharedOUTGate(s_hidden3_2);

	/**
	 Executing the circuit using the ABYParty object evaluate the problem.
	 **/

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

	
	/*int channel=16, size=24;
	ofstream outputfile("./output[0].csv");
	for(int i=0; i<channel; i++){
		for(int j=0; j<size*size; j++){
			if(j==size*size-1){
				outputfile << result[i*size*size+j]  << "\n";
			}else{
				outputfile << result[i*size*size+j] << ",";
			}
		}
	}*/
	

	outputfile.close();

	delete party;

	return 0;

}

/* convolution function */

share* Convolution(share *s_W1, share *s_input, int input_height, int input_width, int input_channel,
		int filter_height, int filter_width, int filter_channel, int filter_num, int bitlen, ArithmeticCircuit *ac, uint32_t *posids, uint32_t *posids_index) {

	share* s_out;
	share* s_kernel;
	share* s_spkernel;
	share* s_part;
	share* s_sparse;

	/* variable to initialize the share */
	uint32_t zero=0;

	/* variable to represent index of result 
		initialize the index */
	int index=0, ind=0;

	s_out = ac->PutSIMDCONSGate((input_height - filter_height+1)*(input_width - filter_width+1)*filter_num, zero, bitlen);
	s_out = ac->PutSplitterGate(s_out);

	s_kernel = ac->PutSIMDCONSGate(filter_height*filter_width*filter_channel, zero, bitlen);

	s_part = ac->PutSIMDCONSGate(filter_height*filter_width*filter_channel, zero, bitlen);
	s_part = ac->PutSplitterGate(s_part);

	s_W1 = ac->PutSplitterGate(s_W1);
	s_input = ac->PutSplitterGate(s_input);


	for(int f_num=0; f_num<filter_num; f_num++){
		/* extract kernel for channel */
		s_kernel = ac->PutSplitterGate(s_kernel);
		for(int i=0; i<filter_height*filter_width*filter_channel; i++){
			s_kernel->set_wire_id(i, s_W1->get_wire_id(f_num*(filter_height*filter_width*filter_channel)+i));
		}
		s_kernel = ac->PutCombinerGate(s_kernel);

		uint32_t *subposids;
		subposids = new uint32_t[posids_index[f_num]];

		for(int x = 0; x < posids_index[f_num]; x++){
			subposids[x] = posids[ind+x];			
		}

		ind = ind + posids_index[f_num];

		s_spkernel = ac->PutSubsetGate(s_kernel, subposids, posids_index[f_num]);

		/* extract input with which multiples kernel */ 
		
		for(int i=0; i<input_height-filter_height+1; i++){
			for(int j=0; j<input_width-filter_width+1; j++){
				for(int c=0; c<filter_channel; c++){
					for(int a=0; a<filter_height; a++){
						for(int b=0; b<filter_width; b++){
							//cout<<k*input_height*input_width+i*input_width+j+input_width*input_height*c+input_width*a+b<<endl;
							//cout<<k<<endl;
							s_part->set_wire_id(filter_height*filter_width*c+filter_width*a+b, 
								s_input->get_wire_id(i*input_width+j+input_width*input_height*c+input_width*a+b));					
						}
					}
				}
				
				s_part = ac->PutCombinerGate(s_part);
				s_sparse = ac->PutSubsetGate(s_part, subposids, posids_index[f_num]);
				s_sparse = ac->PutMULGate(s_spkernel, s_sparse);
				s_sparse = ac->PutSplitterGate(s_sparse);

				s_part = ac->PutSplitterGate(s_part);
				
				/* store the result of convolution */
				for(int l=0; l<posids_index[f_num]; l++){
					s_out->set_wire_id(index, ac->PutADDGate(s_out->get_wire_id(index), s_sparse->get_wire_id(l)));
				}
	 			index++;
	 			
			}
		}	
	}
	s_out = ac->PutCombinerGate(s_out);	
	

	delete s_W1;
	delete s_input;
	delete s_kernel;
	delete s_part; 

	return s_out;
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

/* Batchnormalization + Activation function */
share* BatchnormAct(share *s_x, share *s_y, ArithmeticCircuit *ac){
	
	share *s_out;

	s_out = ac->PutADDGate(s_x, s_y);
	
	delete s_x;
	delete s_y;

	return s_out;
}


/* Batchnormalization function */
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
share* ActivationMax(share *s_x, int height, int width, int channel, int bitlen, ArithmeticCircuit *ac, BooleanCircuit *bc, BooleanCircuit *yc){

	int two = 2, sign = 2147483647, one = 1;

	share *s_two, *s_sign, *s_one, *s_val;

	int num = height*width*channel;
	
	s_two = ac->PutSIMDCONSGate(num, two, bitlen);
	s_sign = yc->PutSIMDCONSGate(num, sign, bitlen);
	s_one = ac->PutSIMDCONSGate(num, one, bitlen);
	
	/* Aritnmetic -> Yao */
	s_x = yc -> PutA2YGate(s_x);
	s_val = yc->PutGTGate(s_sign, s_x);

	uint32_t *posids1;
	uint32_t index1=0;
	uint32_t *posids2;
	uint32_t index2=0;
	uint32_t *posids3;
	uint32_t index3=0;
	uint32_t *posids4;
	uint32_t index4=0;

	posids1 = new uint32_t[num/4];
	posids2 = new uint32_t[num/4];
	posids3 = new uint32_t[num/4];
	posids4 = new uint32_t[num/4];

	for(int h=0; h<height*channel/2; h++){
		for(int w=0; w<width/2; w++){
			posids1[index1] = h*width*2 + w*2;
			index1++;
		}
	}


	for(int h=0; h<height*channel/2; h++){
		for(int w=0; w<width/2; w++){
			posids2[index2] = h*width*2 + w*2 + 1;
			index2++;
		}
	}

	for(int h=0; h<height*channel/2; h++){
		for(int w=0; w<width/2; w++){
			posids3[index3] = width + h*width*2 + w*2;
			index3++;
		}
	}


	for(int h=0; h<height*channel/2; h++){
		for(int w=0; w<width/2; w++){
			posids4[index4] = width + h*width*2 + w*2 + 1;
			index4++;
		}
	}


	share *s_temp1, *s_temp2, *s_maxout;
	s_temp1 = yc->PutSubsetGate(s_val, posids1, num/4);
	s_temp2 = yc->PutSubsetGate(s_val, posids2, num/4);
	s_temp1 = yc->PutORGate(s_temp1, s_temp2);

	s_temp2 = yc->PutSubsetGate(s_val, posids3, num/4);
	s_temp1 = yc->PutORGate(s_temp1, s_temp2);

	s_temp2 = yc->PutSubsetGate(s_val, posids4, num/4);
	s_temp1 = yc->PutORGate(s_temp1, s_temp2);

	/* Yao -> Boolean -> Arithmetic */
	s_maxout = bc -> PutY2BGate(s_temp1);
	s_maxout = ac->PutB2AGate(s_maxout);

	share *s_e, *s_out;
	
	/* 2*s_val-1 */	
	s_e = ac->PutMULGate(s_maxout, s_two);
	s_out = ac->PutSUBGate(s_e, s_one);
	
	delete s_x;
	delete s_two;
	delete s_sign;
	delete s_one;
	delete s_val;
	delete s_temp1;
	delete s_temp2;
	delete s_maxout;
	delete s_e;

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




