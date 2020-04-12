# Program Execution Tracing
Use GCC function call tracing callbacks and BFD to trace program execution, function by function.

Partially based on [EmbeddedFreedom's article on tracing and profiling function calls with GCC](https://balau82.wordpress.com/2010/10/06/trace-and-profile-function-calls-with-gcc/) and [addr2line.c](https://github.com/CyberGrandChallenge/binutils/blob/master/binutils/addr2line.c).

You can get more information on [JehTech](www.jeh-tech.com/c_and_cpp/gcc-instrument-function-calls.html).

To use, add the following lines to the CFLAGS for the program that you wish to trace:
```
CFLAGS +=-O0 -g -finstrument-functions
```

You will also need to either copy and paste `trace_funcs.c` into a file in the program you wish to
trace or include it in the compilation.

Then run the program. It will generate the file `trace.out`.

You can then translate this binary output file into human readable format by compiling and running
parse_trace_output.

```
make # outputs parse_trace_output and installs required dependencies
./parse_trace_output path/to/program/being/traced path/to/trace.out
```