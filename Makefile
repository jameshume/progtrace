.PHONY: all
all: dependencies parse_trace_output.o
	@echo "Linking output"
	@g++ parse_trace_output.o -lbfd -o parse_trace_output

.PHONY: dependencies
dependencies:
	@echo "Checking dependencies"
	@(dpkg -l | grep libiberty-dev > /dev/null) || sudo apt install libiberty-dev
	@(dpkg -l | grep binutils-dev > /dev/null) || sudo apt install binutils-dev