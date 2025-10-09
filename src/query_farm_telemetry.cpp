#include "query_farm_telemetry.hpp"
#include <thread>
#include "duckdb.hpp"
#include "duckdb/common/http_util.hpp"
#include "yyjson.hpp"
#include "duckdb/main/extension_helper.hpp"
#include "duckdb/main/config.hpp"
#include <cstdlib>
using namespace duckdb_yyjson; // NOLINT

namespace duckdb {

static constexpr const char *TARGET_URL = "https://duckdb-in.query-farm.services/";

// Function to send the actual HTTP request
static void sendHTTPRequest(shared_ptr<DatabaseInstance> db, std::string json_body) {
	HTTPHeaders headers;
	headers.Insert("Content-Type", "application/json");

	auto &http_util = HTTPUtil::Get(*db);
	unique_ptr<HTTPParams> params;
	auto target_url = string(TARGET_URL);
	params = http_util.InitializeParameters(*db, target_url);

	PostRequestInfo post_request(target_url, headers, *params, reinterpret_cast<const_data_ptr_t>(json_body.data()),
	                             json_body.size());
	try {
		auto response = http_util.Request(post_request);
	} catch (const std::exception &e) {
		// ignore all errors.
	}

	return;
}

// Public function to start the request thread
static void sendRequestAsync(shared_ptr<DatabaseInstance> db, std::string &json_body) {
	std::thread request_thread(sendHTTPRequest, db, std::move(json_body));
	request_thread.detach(); // Let the thread run independently
}

INTERNAL_FUNC void QueryFarmSendTelemetry(ExtensionLoader &loader, const string &extension_name,
                                          const string &extension_version) {
	const char *opt_out = std::getenv("QUERY_FARM_TELEMETRY_OPT_OUT");
	if (opt_out != nullptr) {
		return;
	}

	auto &dbconfig = DBConfig::GetConfig(loader.GetDatabaseInstance());
	auto old_value = dbconfig.options.autoinstall_known_extensions;
	dbconfig.options.autoinstall_known_extensions = false;
	try {
		ExtensionHelper::AutoLoadExtension(loader.GetDatabaseInstance(), "httpfs");
	} catch (...) {
		dbconfig.options.autoinstall_known_extensions = old_value;
		return;
	}

	dbconfig.options.autoinstall_known_extensions = old_value;
	if (!loader.GetDatabaseInstance().ExtensionIsLoaded("httpfs")) {
		return;
	}

	// Initialize the telemetry sender
	auto doc = yyjson_mut_doc_new(nullptr);

	auto result_obj = yyjson_mut_obj(doc);
	yyjson_mut_doc_set_root(doc, result_obj);

	yyjson_mut_obj_add_str(doc, result_obj, "extension_name", extension_name.c_str());
	yyjson_mut_obj_add_str(doc, result_obj, "extension_version", extension_version.c_str());
	yyjson_mut_obj_add_str(doc, result_obj, "user_agent", "query-farm/20250926");
	yyjson_mut_obj_add_str(doc, result_obj, "duckdb_platform", DuckDB::Platform().c_str());
	yyjson_mut_obj_add_str(doc, result_obj, "duckdb_library_version", DuckDB::LibraryVersion());
	yyjson_mut_obj_add_str(doc, result_obj, "duckdb_release_codename", DuckDB::ReleaseCodename());
	yyjson_mut_obj_add_str(doc, result_obj, "duckdb_source_id", DuckDB::SourceID());

	size_t telemetry_len;
	auto telemetry_data =
	    yyjson_mut_val_write_opts(result_obj, YYJSON_WRITE_ALLOW_INF_AND_NAN, NULL, &telemetry_len, nullptr);

	if (telemetry_data == nullptr) {
		throw SerializationException("Failed to serialize telemetry data.");
	}

	auto telemetry_string = string(telemetry_data, (size_t)telemetry_len);

	yyjson_mut_doc_free(doc);
	free(telemetry_data);

	// Send request asynchronously
	sendRequestAsync(loader.GetDatabaseInstance().shared_from_this(), telemetry_string);
}

} // namespace duckdb