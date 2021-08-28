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
		/* auto res = analysisCb_({
			toString(params.at(U("refGen"))),
			toString(params.at(U("inpGen"))),
			toString(params.at(U("pheno")))
		}); */
		auto res = analysisCb_({
			{
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0002_1_BN_Whole_T3_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0004_1_BN_Whole_C4_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0013_1_PB_Whole_C3_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0014_1_BN_Whole_T2_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0005_1_BN_Whole_T3_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0001_1_BN_Whole_C5_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0003_1_BN_Whole_T4_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0002_1_PB_Whole_C5_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0005_1_PB_Whole_C4_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0012_1_BN_Whole_T3_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0013_1_BN_Whole_T2_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0044_1_PB_Whole_C2_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0041_1_PB_Whole_C3_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0003_1_PB_Whole_C5_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0002_1_BN_Whole_T4_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0004_1_BN_Whole_T5_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0001_1_BN_Whole_T6_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0006_1_BN_Whole_C3_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0007_1_BN_Whole_T2_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0008_1_BN_Whole_C3_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0009_1_BN_Whole_T2_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0012_1_PB_Whole_C4_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0045_1_BN_Whole_T2_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0045_1_BN_Whole_C1_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0044_1_BN_Whole_T1_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0041_1_BN_Whole_T2_KHSC2.bwa.final.chr5.vcf",
				"C:/Users/User/source/repos/GwasSGX/data/vcf/chr5/HPCI_0042_1_PB_Whole_C1_KHSC2.bwa.final.chr5.vcf"
			},
			40,
			100
		});
		
		web::json::value json;
		for (const auto & param : params)
			json[U("parameters")][param.first] = web::json::value(param.second);
		for (size_t i = 0; i < res.samples.size(); ++i) {
			json[U("result")][i][U("snp")] = web::json::value(toStringT(res.samples[i].snp));
			json[U("result")][i][U("val")] = web::json::value(res.samples[i].value);
		}
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
