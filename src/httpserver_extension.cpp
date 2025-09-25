#define DUCKDB_EXTENSION_MAIN
#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <chrono>
#include <cstdlib>
#include <thread>
#include "httpserver_extension.hpp"
#include "query_stats.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/common/allocator.hpp"
#include "result_serializer.hpp"
#include "result_serializer_compact_json.hpp"
#include "httplib.hpp"
#include "yyjson.hpp"
#include "playground.hpp"

#ifndef _WIN32
#include <syslog.h>
#endif
#include "query_farm_telemetry.hpp"

namespace duckdb {

using namespace duckdb_yyjson; // NOLINT(*-build-using-namespace)

struct HttpServerState {
	std::unique_ptr<duckdb_httplib_openssl::Server> server;
	std::unique_ptr<std::thread> server_thread;
	std::atomic<bool> is_running;
	shared_ptr<DatabaseInstance> db_instance;
	unique_ptr<Allocator> allocator;
	std::string auth_token;

	HttpServerState() : is_running(false), db_instance(nullptr) {
	}
};

static HttpServerState global_state;

// Base64 decoding function
std::string base64_decode(const std::string &in) {
	std::string out;
	std::vector<int> T(256, -1);
	for (int i = 0; i < 64; i++)
		T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

	int val = 0, valb = -8;
	for (unsigned char c : in) {
		if (T[c] == -1)
			break;
		val = (val << 6) + T[c];
		valb += 6;
		if (valb >= 0) {
			out.push_back(char((val >> valb) & 0xFF));
			valb -= 8;
		}
	}
	return out;
}

// Auth Check
bool IsAuthenticated(const duckdb_httplib_openssl::Request &req) {
	if (global_state.auth_token.empty()) {
		return true; // No authentication required if no token is set
	}

	// Check for X-API-Key header
	auto api_key = req.get_header_value("X-API-Key");
	if (!api_key.empty() && api_key == global_state.auth_token) {
		return true;
	}

	// Check for Basic Auth
	auto auth = req.get_header_value("Authorization");
	if (!auth.empty() && auth.compare(0, 6, "Basic ") == 0) {
		std::string decoded_auth = base64_decode(auth.substr(6));
		if (decoded_auth == global_state.auth_token) {
			return true;
		}
	}

	return false;
}

// Convert the query result to NDJSON (JSONEachRow) format
static std::string ConvertResultToNDJSON(MaterializedQueryResult &result) {
	std::string ndjson_output;

	for (idx_t row = 0; row < result.RowCount(); ++row) {
		// Create a new JSON document for each row
		auto doc = yyjson_mut_doc_new(nullptr);
		auto root = yyjson_mut_obj(doc);
		yyjson_mut_doc_set_root(doc, root);

		for (idx_t col = 0; col < result.ColumnCount(); ++col) {
			Value value = result.GetValue(col, row);
			const char *column_name = result.ColumnName(col).c_str();

			// Handle null values and add them to the JSON object
			if (value.IsNull()) {
				yyjson_mut_obj_add_null(doc, root, column_name);
			} else {
				// Convert value to string and add it to the JSON object
				std::string value_str = value.ToString();
				yyjson_mut_obj_add_strncpy(doc, root, column_name, value_str.c_str(), value_str.length());
			}
		}

		char *json_line = yyjson_mut_write(doc, 0, nullptr);
		if (!json_line) {
			yyjson_mut_doc_free(doc);
			throw InternalException("Failed to render a row as JSON, yyjson failed");
		}

		ndjson_output += json_line;
		ndjson_output += "\n";

		// Free allocated memory for this row
		free(json_line);
		yyjson_mut_doc_free(doc);
	}

	return ndjson_output;
}

static std::string ConvertResultToCSV(MaterializedQueryResult &result) {
	std::string csv_output;

	// Add header row
	for (idx_t col = 0; col < result.ColumnCount(); ++col) {
		if (col > 0) {
			csv_output += ",";
		}
		csv_output += result.ColumnName(col);
	}
	csv_output += "\n";

	// Add data rows
	for (idx_t row = 0; row < result.RowCount(); ++row) {
		for (idx_t col = 0; col < result.ColumnCount(); ++col) {
			if (col > 0) {
				csv_output += ",";
			}
			Value value = result.GetValue(col, row);
			if (value.IsNull()) {
				// Leave empty for NULL values
				continue;
			}

			std::string value_str = value.ToString();
			// Escape quotes and wrap in quotes if contains special characters
			if (value_str.find_first_of(",\"\n\r") != std::string::npos) {
				std::string escaped;
				escaped.reserve(value_str.length() + 2);
				escaped += '"';
				for (char c : value_str) {
					if (c == '"') {
						escaped += '"'; // Double the quotes to escape
					}
					escaped += c;
				}
				escaped += '"';
				csv_output += escaped;
			} else {
				csv_output += value_str;
			}
		}
		csv_output += "\n";
	}

	return csv_output;
}

static std::string EscapeXML(const std::string &in) {
	std::string out;
	out.reserve(in.size());
	for (char c : in) {
		switch (c) {
		case '&':
			out += "&amp;";
			break;
		case '<':
			out += "&lt;";
			break;
		case '>':
			out += "&gt;";
			break;
		case '"':
			out += "&quot;";
			break;
		case '\'':
			out += "&apos;";
			break;
		default:
			out += c;
			break;
		}
	}
	return out;
}

static std::string ConvertResultToXML(MaterializedQueryResult &result) {
	std::string xml;
	xml += "<results>\n";

	for (idx_t row = 0; row < result.RowCount(); ++row) {
		xml += "  <row>\n";

		for (idx_t col = 0; col < result.ColumnCount(); ++col) {
			const std::string &col_name = result.ColumnName(col); // keep original
			Value val = result.GetValue(col, row);

			xml += "    <column name=\"";
			xml += EscapeXML(col_name);
			xml += "\">";

			if (!val.IsNull()) {
				xml += EscapeXML(val.ToString());
			}

			xml += "</column>\n";
		}
		xml += "  </row>\n";
	}

	xml += "</results>\n";
	return xml;
}

// Handle both GET and POST requests
void HandleHttpRequest(const duckdb_httplib_openssl::Request &req, duckdb_httplib_openssl::Response &res) {
	std::string query;

	// CORS allow - set these headers for all requests
	res.set_header("Access-Control-Allow-Origin", "*");
	res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT");
	res.set_header("Access-Control-Allow-Headers", "*");
	res.set_header("Access-Control-Allow-Credentials", "true");
	res.set_header("Access-Control-Max-Age", "86400");

	// Check authentication for actual requests (OPTIONS are handled separately)
	if (!IsAuthenticated(req)) {
		res.status = 401;
		res.set_content("Unauthorized", "text/plain");
		return;
	}

	// Check if the query is in the URL parameters
	if (req.has_param("query")) {
		query = req.get_param_value("query");
	} else if (req.has_param("q")) {
		query = req.get_param_value("q");
	}
	// If not in URL, and it's a POST request, check the body
	else if (req.method == "POST" && !req.body.empty()) {
		query = req.body;
	}
	// If no query found, return an error
	else {
		res.status = 200;
		res.set_content(reinterpret_cast<char const *>(playgroundContent), "text/html");
		return;
	}

	// Set default format to JSONEachRow
	std::string format = "JSONEachRow";

	// Check for format in URL parameter or header
	if (req.has_param("default_format")) {
		format = req.get_param_value("default_format");
	} else if (req.has_header("X-ClickHouse-Format")) {
		format = req.get_header_value("X-ClickHouse-Format");
	} else if (req.has_header("format")) {
		format = req.get_header_value("format");
	}

	try {
		if (!global_state.db_instance) {
			throw IOException("Database instance not initialized");
		}

		Connection con(*global_state.db_instance);
		auto start = std::chrono::system_clock::now();
		auto result = con.Query(query);
		auto end = std::chrono::system_clock::now();
		auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

		if (result->HasError()) {
			res.status = 500;
			res.set_content(result->GetError(), "text/plain");
			return;
		}

		ReqStats stats {static_cast<float>(elapsed.count()) / 1000, 0, 0};

		// Format Options
		if (format == "JSONEachRow") {
			std::string json_output = ConvertResultToNDJSON(*result);
			res.set_content(json_output, "application/x-ndjson");
		} else if (format == "JSONCompact") {
			ResultSerializerCompactJson serializer;
			std::string json_output = serializer.Serialize(*result, stats);
			res.set_content(json_output, "application/json");
		} else if (format == "CSV") {
			std::string csv_output = ConvertResultToCSV(*result);
			res.set_header("Content-Type", "text/csv");
			res.set_content(csv_output, "text/csv");
		} else if (format == "XML") {
			std::string xml_output = ConvertResultToXML(*result);
			res.set_header("Content-Type", "application/xml");
			res.set_content(xml_output, "application/xml");
		} else {
			// Default to NDJSON for DuckDB's own queries
			std::string json_output = ConvertResultToNDJSON(*result);
			res.set_content(json_output, "application/x-ndjson");
		}

	} catch (const Exception &ex) {
		res.status = 500;
		std::string error_message = "DB::Exception: " + std::string(ex.what());
		res.set_content(error_message, "text/plain");
	}
}

void HttpServerStart(shared_ptr<DatabaseInstance> db, string_t host, int32_t port, string_t auth = string_t()) {
	if (global_state.is_running) {
		throw IOException("HTTP server is already running");
	}

	global_state.db_instance = db;
	global_state.server = make_uniq<duckdb_httplib_openssl::Server>();
	global_state.is_running = true;
	global_state.auth_token = auth.GetString();

	// Custom basepath, defaults to root /
	const char *base_path_env = std::getenv("DUCKDB_HTTPSERVER_BASEPATH");
	std::string base_path = "/";

	if (base_path_env && base_path_env[0] == '/' && strlen(base_path_env) > 1) {
		base_path = std::string(base_path_env);
		// Ensure trailing slash for consistent endpoint joining
		if (base_path.back() != '/') {
			base_path += '/';
		}
	}

	// CORS Preflight - no authentication required for OPTIONS requests
	global_state.server->Options(
	    base_path, [](const duckdb_httplib_openssl::Request & /*req*/, duckdb_httplib_openssl::Response &res) {
		    res.set_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT");
		    res.set_header("Content-Type", "text/html; charset=utf-8");
		    res.set_header("Access-Control-Allow-Headers", "*");
		    res.set_header("Access-Control-Allow-Origin", "*");
		    res.set_header("Access-Control-Allow-Credentials", "true");
		    res.set_header("Connection", "close");
		    res.status = 204; // No content for preflight
		    return duckdb_httplib_openssl::Server::HandlerResponse::Handled;
	    });

	// Create a new allocator for the server thread
	global_state.allocator = make_uniq<Allocator>();

	// Handle GET and POST requests
	global_state.server->Get(base_path, HandleHttpRequest);
	global_state.server->Post(base_path, HandleHttpRequest);

	// Health check endpoint - no authentication required
	global_state.server->Get(base_path + "ping",
	                         [](const duckdb_httplib_openssl::Request &req, duckdb_httplib_openssl::Response &res) {
		                         // Set CORS headers for health check endpoint
		                         res.set_header("Access-Control-Allow-Origin", "*");
		                         res.set_header("Access-Control-Allow-Methods", "GET, OPTIONS");
		                         res.set_header("Access-Control-Allow-Headers", "Content-Type");
		                         res.set_header("Access-Control-Allow-Credentials", "true");
		                         res.set_content("OK", "text/plain");
	                         });

	string host_str = host.GetString();

#ifndef _WIN32
	const char *debug_env = std::getenv("DUCKDB_HTTPSERVER_DEBUG");
	const char *use_syslog = std::getenv("DUCKDB_HTTPSERVER_SYSLOG");

	if (debug_env != nullptr && std::string(debug_env) == "1") {
		global_state.server->set_logger(
		    [](const duckdb_httplib_openssl::Request &req, const duckdb_httplib_openssl::Response &res) {
			    // Get current time with timezone offset
			    time_t now_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
			    struct tm *tm_info = localtime(&now_time);
			    char timestr[32];
			    char timezone[8];
			    strftime(timestr, sizeof(timestr), "%d/%b/%Y:%H:%M:%S", tm_info);
			    strftime(timezone, sizeof(timezone), "%z", tm_info);

			    size_t response_size = 0;
			    if (!res.body.empty()) {
				    response_size = res.body.size();
			    }
			    std::string user_agent = req.has_header("User-Agent") ? req.get_header_value("User-Agent") : "-";
			    std::string referer = req.has_header("Referer") ? req.get_header_value("Referer") : "-";
			    std::string forwarded_for =
			        req.has_header("X-Forwarded-For") ? req.get_header_value("X-Forwarded-For") : "-";
			    fprintf(stdout, "%s - - [%s %s] \"%s %s HTTP/%s\" %d %zu \"%s\" \"%s\" \"%s\"\r\n",
			            req.remote_addr.c_str(), // IP address
			            timestr,                 // Timestamp
			            timezone,                // Timezone offset
			            req.method.c_str(),      // HTTP method
			            req.path.c_str(),        // Request path
			            req.version.c_str(),     // HTTP version
			            res.status,              // Status code
			            response_size,           // Response size
			            referer.c_str(),         // Referer
			            user_agent.c_str(),      // User Agent
			            forwarded_for.c_str()    // X-Forwarded-For
			    );
			    fflush(stdout);
		    });
	} else if (use_syslog != nullptr && std::string(use_syslog) == "1") {
		openlog("duckdb-httpserver", LOG_PID | LOG_NDELAY, LOG_LOCAL0);
		global_state.server->set_logger(
		    [](const duckdb_httplib_openssl::Request &req, const duckdb_httplib_openssl::Response &res) {
			    size_t response_size = 0;
			    if (!res.body.empty()) {
				    response_size = res.body.size();
			    }
			    std::string user_agent = req.has_header("User-Agent") ? req.get_header_value("User-Agent") : "-";
			    std::string referer = req.has_header("Referer") ? req.get_header_value("Referer") : "-";
			    std::string forwarded_for =
			        req.has_header("X-Forwarded-For") ? req.get_header_value("X-Forwarded-For") : "-";

			    syslog(LOG_INFO, "%s - - \"%s %s HTTP/%s\" %d %zu \"%s\" \"%s\" \"%s\"", req.remote_addr.c_str(),
			           req.method.c_str(), req.path.c_str(), req.version.c_str(), res.status, response_size,
			           referer.c_str(), user_agent.c_str(), forwarded_for.c_str());
		    });
		std::atexit([]() { closelog(); });
	}
#endif

	const char *run_in_same_thread_env = std::getenv("DUCKDB_HTTPSERVER_FOREGROUND");
	bool run_in_same_thread = (run_in_same_thread_env != nullptr && std::string(run_in_same_thread_env) == "1");

	if (run_in_same_thread) {
#ifdef _WIN32
		throw IOException("Foreground mode not yet supported on WIN32 platforms.");
#else
		// POSIX signal handler for SIGINT (Linux/macOS)
		signal(SIGINT, [](int) {
			if (global_state.server) {
				global_state.server->stop();
			}
			global_state.is_running = false; // Update the running state
		});

		// Run the server in the same thread
		if (!global_state.server->listen(host_str.c_str(), port)) {
			global_state.is_running = false;
			throw IOException("Failed to start HTTP server on " + host_str + ":" + std::to_string(port));
		}
#endif

		// The server has stopped (due to CTRL-C or other reasons)
		global_state.is_running = false;
	} else {
		// Run the server in a dedicated thread (default)
		global_state.server_thread = make_uniq<std::thread>([host_str, port]() {
			if (!global_state.server->listen(host_str.c_str(), port)) {
				global_state.is_running = false;
				throw IOException("Failed to start HTTP server on " + host_str + ":" + std::to_string(port));
			}
		});
	}
}

void HttpServerStop() {
	if (global_state.is_running) {
		global_state.server->stop();
		if (global_state.server_thread && global_state.server_thread->joinable()) {
			global_state.server_thread->join();
		}
		global_state.server.reset();
		global_state.server_thread.reset();
		global_state.db_instance = nullptr;
		global_state.is_running = false;

		// Reset the allocator
		global_state.allocator.reset();
	}
}

static void HttpServerCleanup() {
	HttpServerStop();
}

static void LoadInternal(ExtensionLoader &loader) {
	auto httpserve_start = ScalarFunction(
	    "httpserve_start", {LogicalType::VARCHAR, LogicalType::INTEGER, LogicalType::VARCHAR}, LogicalType::VARCHAR,
	    [&](DataChunk &args, ExpressionState &state, Vector &result) {
		    auto &host_vector = args.data[0];
		    auto &port_vector = args.data[1];
		    auto &auth_vector = args.data[2];

		    UnaryExecutor::Execute<string_t, string_t>(host_vector, result, args.size(), [&](string_t host) {
			    auto port = ((int32_t *)port_vector.GetData())[0];
			    auto auth = ((string_t *)auth_vector.GetData())[0];
			    HttpServerStart(loader.GetDatabaseInstance().shared_from_this(), host, port, auth);
			    return StringVector::AddString(result, "HTTP server started on " + host.GetString() + ":" +
			                                               std::to_string(port));
		    });
	    });

	auto httpserve_stop = ScalarFunction("httpserve_stop", {}, LogicalType::VARCHAR,
	                                     [](DataChunk &args, ExpressionState &state, Vector &result) {
		                                     HttpServerStop();
		                                     result.SetValue(0, Value("HTTP server stopped"));
	                                     });

	loader.RegisterFunction(httpserve_start);
	loader.RegisterFunction(httpserve_stop);

	QueryFarmSendTelemetry(loader, loader.GetDatabaseInstance().shared_from_this(), "httpserver", "2025092401");

	// Register the cleanup function to be called at exit
	std::atexit(HttpServerCleanup);
}

void HttpserverExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

std::string HttpserverExtension::Name() {
	return "httpserver";
}

std::string HttpserverExtension::Version() const {
	return "2025092401";
}

} // namespace duckdb

extern "C" {
DUCKDB_CPP_EXTENSION_ENTRY(httpserver, loader) {
	duckdb::LoadInternal(loader);
}
}
