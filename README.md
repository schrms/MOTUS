# SecureBNN-TNN
## [how to install]
1. launch two c4.8xlarge instances (AmazonEC2) and set each IP address as IP1, IP2 set as follow in each instance
2. git clone ABY.git
3. git checkout 104f2ec9bee9ab2b4208913f4076eea282c14154
4. git submodule update --init --recursive
5. uncomment the ABY/src/abycore/ABY_utils/ABYconstants.h:29 enable "#define PRINT_OUTPUT" 
6. put the repository in the same folder as ABY
7. cd ABY
8. make
9. cd ../"repository name"
10. make

## [how to execute]
Arc1
1. cd MNIST_Arc1/bin
2. ./MNIST_Arc1 -r 0 -a {IP1} [-n {the number of neuron}]
3. ./MNIST_Arc1 -r 1 -a {IP1} [-n {the number of neuron}]

Arc1_partial
1. cd MNIST_Arc1_partial/bin
2. ./MNIST_Arc1_partial -r 0 -a {IP1} [-n {the number of neuron}]
3. ./MNIST_Arc1_partial -r 1 -a {IP1} [-n {the number of neuron}]

The default number of neuron is 128.
The maximum number of neuron is 1000.

otherwise
1. cd "repository name"/bin
2. ./repository name -r 0 -a {IP1}
3. ./repository name -r 1 -a {IP1} 

## [how to evaluate experimental result]
This program outputs three benchmarks. If you want to check the secure prediction benchmark, you can look at the second benchmark.
