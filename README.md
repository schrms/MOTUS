# SecureBNN-TNN
## [how to install]
1. launch two c4.8xlarge instances (AmazonEC2) and set each IP address as IP1, IP2 set as follow in each instance
2. git clone ABY.git
3. git checkout 104f2ec9bee9ab2b4208913f4076eea282c14154
4. git submodule update --init --recursive
5. uncomment the ABY/src/abycore/ABY_utils/ABYconstants.h:29 enable "#define PRINT_OUTPUT" 
6. put the BNN_Mnist_Secure_prediction, BNN_Cancer_Secure_prediction and BNN_Diabetes_Secure_prediction in the same folder as ABY
7. cd ABY
8. make
9. cd ../BNN_Mnist_Secure_prediction or ../BNN_Cancer_Secure_prediction or ../BNN_Diabetes_Secure_prediction
10. make

## [how to execute]
Mnist dataset
1. cd BNN_Mnist_Secure_prediction/bin
2-a. ./BNN_Mnist_Secure_prediction -r 0 -a {IP1} [-n {the number of neuron}]
2-b. ./BNN_Mnist_Secure_prediction -r 1 -a {IP1} [-n {the number of neuron}]
The default number of neuron is 128.
The maximum number of neuron is 1000.

Cancer dataset
1. cd BNN_Cancer_Secure_prediction/bin
2-a. ./BNN_Cancer_Secure_prediction -r 0 -a {IP1}
2-b. ./BNN_Cancer_Secure_prediction -r 1 -a {IP1} 
The default number of neuron is 2.
The maximum number of neuron is 2.

Diabetes dataset
1. cd BNN_Diabetes_Secure_prediction/bin
2-a. ./BNN_Diabetes_Secure_prediction -r 0 -a {IP1}
2-b. ./BNN_Diabetes_Secure_prediction -r 1 -a {IP1} 
The default number of neuron is 10.
The maximum number of neuron is 10.

## [how to evaluate experimental result]
This program outputs three benchmarks. If you want to check the secure prediction benchmark, you can look at the second benchmark.
