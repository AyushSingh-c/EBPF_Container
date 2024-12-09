CXX = clang++
CXXFLAGS = -Wall -ggdb -O1 -std=c++17 -I$(ROOT_DIR)
CPP_SRCS = $(wildcard *.cpp)
CPP_OBJS = $(patsubst %.cpp,$(ROOT_DIR)/bin/src/%.o,$(CPP_SRCS))
LDFLAGS = -lbpf -lstdc++ -lpthread -g -lelf
UTIL_SRC_DIR = $(ROOT_DIR)/src/utils
UTIL_SRC_OBJS = $(patsubst $(UTIL_SRC_DIR)/%.cpp,$(ROOT_DIR)/bin/src/utils/%.o,$(wildcard $(UTIL_SRC_DIR)/*.cpp))
TARGET = $(ROOT_DIR)/bin/sensor

all: utils kern_code $(BPF_OBJS) $(TARGET)

utils:
	$(MAKE) -C utils ROOT_DIR=$(ROOT_DIR)
kern_code:
	$(MAKE) -C kern_code ROOT_DIR=$(ROOT_DIR)

$(ROOT_DIR)/bin/src/%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(TARGET): $(CPP_OBJS)
	$(CXX) $(CPP_OBJS) $(UTIL_SRC_OBJS) $(LDFLAGS) -o $@

.PHONY: utils kern_code clean
clean:
	$(MAKE) -C utils clean
	$(MAKE) -C kern_code clean
	rm -f $(BPF_OBJS) $(CPP_OBJS) $(TARGET)
