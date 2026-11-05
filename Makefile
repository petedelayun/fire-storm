CXX       ?= g++
CXXFLAGS   = -std=c++17 -O2 -Wall -Wextra
DEBUGFLAGS = -std=c++17 -g -Wall -Wextra -fsanitize=address,undefined

TARGETS = stage1/firestorm stage2/firestorm

.PHONY: all debug clean

all: $(TARGETS)

stage1/firestorm: stage1/main.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

stage2/firestorm: stage2/main.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

debug: CXXFLAGS = $(DEBUGFLAGS)
debug: clean $(TARGETS)

clean:
	rm -f $(TARGETS) stage1/*.pdf stage2/*.pdf