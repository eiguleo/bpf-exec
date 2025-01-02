# compile
clang -o get-index get-index.c  
clang -O2 -Wall -target bpf -c xdp-example.c -o xdp-example.o

# get interface index
./get-index


# apply
sudo ip link set dev eth0 xdp obj xdp-example.o

# remove
sudo ip link set dev eth0 xdp off

