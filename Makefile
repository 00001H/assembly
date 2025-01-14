COMPOPT := -std=c++26 -flto -fuse-linker-plugin -Wall -Wextra -Wpedantic -m64 -O3 -I"src" $(cppinclude)
FINALOPT := $(COMPOPT) -s -static
HEADERS := $(wildcard *.hpp)
ifeq ($(OS),"Windows_NT")
TARGET_SUFFIX := .exe
else
TARGET_SUFFIX :=
endif
test$(TARGET_SUFFIX): test.cpp
	g++ $< $(OBJECTS) -o $@ $(FINALOPT)
%.o: %.cpp $(HEADERS)
