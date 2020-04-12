/*
 * Based on article & code found on FreedomEmbeedded here:
 *    https://balau82.wordpress.com/2010/10/06/trace-and-profile-function-calls-with-gcc/
 *
 * Modifications made to
 *   a) Add a thread identifier to each function entry/exit, and
 *   b) Use a binary logging format.
 *
 * Note - This will produce an absolute shed tonne of data. On event fairly small projects you
 *        could expect the output trace file to run into GIGABYTES, so be a little cautious how
 *        you use it.
 *
 *        To limit this you'll have to add some filtering to the function entry/exit callbacks.
 *        One idea could be to have a list of address ranges filled with dummy values. Compile
 *        your program and the use objdump to get the actual address ranges you want (taking 
 *        into account program load offset) and substitute these in for the dummy values and filter
 *        on these.
 */
#if defined(__GNUC__) || defined(__GNUG__)

extern "C" {
	#include <stdio.h>
	#include <pthread.h>

	static FILE *fp_trace;
	static pthread_mutex_t lock;

	/*
	 * \brief Gets called before main() but after anything in the .init section, so we know C
	 *        runtime is initialised.
	 *
	 * Opens the output binary file trace.out for writing and creates a mutex so that that the
	 * functions are thread safe, otherwise trace.out will get garbelled.
	 *
	 * \post Outputs uint32_t, uint32_t, uint32_t, uint32_t, void* to binary log
	 *       First 4 uint32_t's are just a magic number header
	 *       Last void* is the address of main(). Will be used by trace reader to determine the
	 *       load offset as addresses written here will be relative to the load address of the
	 *       program being traced.
	 */
	void __attribute__((constructor)) trace_begin(void)
	{
		if (pthread_mutex_init(&lock, NULL) == 0)
		{
			fp_trace = fopen("trace.out", "w");
			if (fp_trace == NULL)
			{
				pthread_mutex_destroy(&lock);
			}
			else
			{
				extern int main(int, char **);
				void *const main_ptr = (void *)main;
				const uint32_t header[4] = { 0x4a656854, 0x6563682d, 0x42696e54, 0x72616365 }; // "JehTech-BinTrace"
				fwrite(&header, sizeof(header), 1, fp_trace);
				fwrite(&main_ptr, sizeof(void *), 1, fp_trace);
			}
		}
	}

	/*
	 * \brief called after main() exits. Just closes the mutex and file if they are open.
	 */
	void __attribute__((destructor)) trace_end(void)
	{
		if (fp_trace != NULL)
		{
			fclose(fp_trace);
			pthread_mutex_destroy(&lock);
		}
	}


	/*
	 * \brief Called by GCC when a function is called.
	 * \param func   - a pointer to the function that was just entered
	 * \param caller - a pointer to the call site
	 * \post Outputs uint8_t, void*, void*, void* to binary log
	 */
	void __cyg_profile_func_enter(void *func, void *caller)
	{
		if (fp_trace != NULL)
		{
			pthread_mutex_lock(&lock); 
			static const uint8_t entry_marker = 0x55;
			const pthread_t self = pthread_self();
			const void * buffer[3] = { (void *)self, func, caller };
			fwrite((void *)&entry_marker, sizeof(entry_marker), 1, fp_trace);
			fwrite((void *)buffer, sizeof(buffer), 1, fp_trace);
			pthread_mutex_unlock(&lock); 
		}
	}

	/*
	 * \brief Called by GCC when a function exits.
	 * \param func   - a pointer to the function that was just left
	 * \param caller - a pointer to the call site
	 * \post Outputs uint8_t, void*, void*, void* to binary log
	 */
	void __cyg_profile_func_exit(void *func, void *caller)
	{
		if (fp_trace != NULL)
		{
			pthread_mutex_lock(&lock); 
			static const uint8_t exit_marker = 0xaa;
			const pthread_t self = pthread_self();
			const void * buffer[3] = { (void *)self, func, caller };
			fwrite((void *)&exit_marker, sizeof(exit_marker), 1, fp_trace);
			fwrite((void *)buffer, sizeof(buffer), 1, fp_trace);
			pthread_mutex_unlock(&lock); 
		}
	}
}
#endif
