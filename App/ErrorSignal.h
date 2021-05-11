#ifndef ERROR_SIGNAL_H_
#define ERROR_SIGNAL_H_

#include "sgx_urts.h"

namespace ErrorSignal
{

	typedef struct _sgx_errlist_t {
		sgx_status_t err;
		const char * msg;
		const char * sug;
	} sgx_errlist_t;

	void print_error_message(sgx_status_t ret);

} // namespace ErrorSignal

#endif // ERROR_SIGNAL_H_
