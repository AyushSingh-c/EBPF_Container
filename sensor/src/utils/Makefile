CXX = clang++
CXXFLAGS = -Wall -ggdb -O1 -std=c++17 -O1 -I$(ROOT_DIR)
CPP_SRCS = $(wildcard *.cpp)
CPP_OBJS = $(patsubst %.cpp,$(ROOT_DIR)/bin/src/utils/%.o,$(CPP_SRCS))

all: $(CPP_OBJS)

$(ROOT_DIR)/bin/src/utils/%.o: %.cpp
	mkdir -p $(ROOT_DIR)/bin/src/utils
	$(CXX) $(CXXFLAGS) -c -o $@ $^

.PHONY: clean
clean:
	rm -f $(CPP_OBJS)
