#include "Server.h"
#include "ServerFrontEnd.h"

#include <cpprest/uri.h>
#include <cpprest/http_listener.h>
#include <cpprest/asyncrt_utils.h>

#include <stdio.h>

#pragma comment(lib, "cpprest_2_10.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "httpapi.lib")

namespace
{
	std::string toString(const utility::string_t & str_t) {
		return utility::conversions::to_utf8string(str_t);
	}

	utility::string_t toStringT(const std::string & str) {
		return utility::conversions::to_string_t(str);
	}
}


GwasServer::GwasServer(AnalysisCallback cb)
	: analysisCb_(cb)
{
	utility::string_t server_addr = U(SERVER_URI);
	auto uri = web::uri_builder(server_addr);
	listener_ = new HttpListener(uri.to_uri().to_string());
	listener_->support(HttpMethod::GET, std::bind(&GwasServer::process, this, std::placeholders::_1));
}

auto GwasServer::open() -> AsyncTask
{
	return listener_->open();
}

auto GwasServer::close() -> AsyncTask
{
	return listener_->close();
}

void GwasServer::process(const HttpRequest & msg)
{
	using namespace web::http;
	_print_request_info(msg);
	auto path = uri::split_path(uri::decode(msg.relative_uri().path()));
	if (path.empty())
		processFrontEnd(msg);
	else if (path[0] == U("analyse"))
		processGwasAnalysis(msg);
	else if (path[0] == U("favicon.ico"))
		processFavicon(msg);
	else
		msg.reply(web::http::status_codes::BadGateway, "No resource at this address");
}

void GwasServer::processFrontEnd(const HttpRequest & msg)
{
	auto body = toStringT(ServerFrontEnd::formPage());
	msg.reply(web::http::status_codes::OK, body, U("text/html"));
}

void GwasServer::processGwasAnalysis(const HttpRequest & msg)
{
	using namespace web::http;
	auto params = uri::split_query(uri::decode(msg.relative_uri().query()));
	AsyncTask([this, params, msg]() {

		// Parse list of files
		std::vector<std::string> list_of_files;
		auto files = toString(params.at(U("files")));
		size_t it_pos = 0, delim_pos = files.find('\r\n');
		do {
			list_of_files.push_back(files.substr(it_pos, delim_pos - it_pos));
			it_pos = delim_pos + 2;
			delim_pos = files.find('\r\n', it_pos);
		} while (delim_pos != -1);
		list_of_files.push_back(files.substr(it_pos, delim_pos - it_pos));

		// Parse remaining arguments
		auto reference_genome = toString(params.at(U("mapq")));
		auto region_of_interest = std::make_pair(
			std::stoi(params.at(U("roi_begin"))),
			std::stoi(params.at(U("roi_end")))
		);
		auto map_quality = std::stoi(params.at(U("mapq")));
		auto return_output = params.find(U("return")) != params.end();

		auto res = analysisCb_({
			reference_genome,
			std::move(list_of_files),
			std::move(region_of_interest),
			map_quality,
			return_output
		});
		
		web::json::value json;
		for (const auto & param : params)
			json[U("parameters")][param.first] = web::json::value(param.second);
		/* for (size_t i = 0; i < res.samples.size(); ++i) {
			json[U("result")][i][U("snp")] = web::json::value(toStringT(res.samples[i].snp));
			json[U("result")][i][U("val")] = web::json::value(res.samples[i].value);
		} */
		json[U("result")] = web::json::value(toStringT(res.result));
		msg.reply(web::http::status_codes::OK, json);
	});
}

void GwasServer::processFavicon(const HttpRequest & msg)
{
	msg.reply(web::http::status_codes::OK, U(""), U("image/x-icon"));
}

void GwasServer::_print_request_info(const HttpRequest & msg)
{
	auto path = web::http::uri::decode(msg.relative_uri().path());
	auto params = web::http::uri::decode(msg.relative_uri().query());
	ucout << "|| Processing " << msg.method() << " request";
	ucout << " | path:";
	for (const auto & pathItem : web::uri::split_path(path))
		ucout << " " << pathItem;
	ucout << " | params:";
	for (const auto & queryItem : web::uri::split_query(params))
		ucout << " (" << queryItem.first << "," << queryItem.second << ")";
	ucout << "||" << std::endl;
}
