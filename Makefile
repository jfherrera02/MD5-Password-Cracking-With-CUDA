CC = gcc
NVCC = nvcc

CFLAGS = -Wall -O2
NVFLAGS = -O2 -std=c++11

SEQ_TARGET = sequential
CUDA_TARGET = cuda_md5

SEQ_SRC = sequential.c
CUDA_SRC = cuda_md5.cu

all: $(SEQ_TARGET) $(CUDA_TARGET)

$(SEQ_TARGET): $(SEQ_SRC)
	$(CC) $(CFLAGS) $(SEQ_SRC) -o $(SEQ_TARGET)

$(CUDA_TARGET): $(CUDA_SRC)
	$(NVCC) $(NVFLAGS) $(CUDA_SRC) -o $(CUDA_TARGET)

clean:
	rm -f $(SEQ_TARGET) $(CUDA_TARGET)

