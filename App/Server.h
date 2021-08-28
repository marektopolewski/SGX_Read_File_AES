#ifndef SERVER_H
#define SERVER_H

#include "App.h"

#include "pplx/pplxtasks.h"

#define SERVER_URI "http://*:8080"

namespace web {
	namespace http {
		class methods;
		class http_request;
		namespace experimental {
			namespace listener { class http_listener; }
		}
	}
}

class GwasServer
{
public:
	using AsyncTask = pplx::task<void>;
	using HttpRequest = web::http::http_request;
	using HttpListener = web::http::experimental::listener::http_listener;
	using HttpMethod = web::http::methods;

	GwasServer(AnalysisCallback cb);
	AsyncTask open();
	AsyncTask close();

private:
	void process(const HttpRequest & msg);
	void processFrontEnd(const HttpRequest & msg);
	void processGwasAnalysis(const HttpRequest & msg);
	void processFavicon(const HttpRequest & msg);

	void _print_request_info(const HttpRequest & msg);

	AnalysisCallback analysisCb_;
	HttpListener * listener_;
};

#endif // SERVER_H
