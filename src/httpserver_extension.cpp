#define DUCKDB_EXTENSION_MAIN
#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>
#include "httpserver_extension.hpp"
#include "query_stats.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_state.hpp"
#include "duckdb/main/database.hpp"
#include "duckdb/main/settings.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"
#include "duckdb/storage/object_cache.hpp"
#include "result_serializer.hpp"
#include "result_serializer_compact_json.hpp"
#include "result_serializer_json_each_row.hpp"
#include "httplib.hpp"
#include "playground.hpp"

#ifndef _WIN32
#include <syslog.h>
#endif
#include "query_farm_telemetry.hpp"

namespace duckdb
{

	static constexpr const char *HTTPSERVER_VERSION = "2026110701";

	static constexpr const char *ALLOWED_ORIGINS_SETTING = "httpserver_allowed_origins";
	static constexpr const char *ALLOW_UNAUTHENTICATED_REMOTE_SETTING = "httpserver_allow_unauthenticated_remote";
	static constexpr const char *TLS_CERT_SETTING = "httpserver_tls_cert";
	static constexpr const char *TLS_KEY_SETTING = "httpserver_tls_key";

	using HttpServer = duckdb_httplib_openssl::Server;
	using HttpRequest = duckdb_httplib_openssl::Request;
	using HttpResponse = duckdb_httplib_openssl::Response;

	// Set while a server thread handles a request, so a database whose last reference is dropped by a request
	// doesn't join the server's own threads from one of them.
	static thread_local bool in_server_request = false;

	// Marks the connections that run served queries. httpserve_stop() called from such a query would wait for
	// the request (and so itself) to finish. Scalar functions can run on any DuckDB worker thread, so this is
	// tracked on the connection rather than the thread.
	class ServedConnectionMarker : public ClientContextState
	{
	public:
		static constexpr const char *KEY = "httpserver_served_connection";
	};

	struct ServerRequestScope
	{
		ServerRequestScope()
		{
			in_server_request = true;
		}
		~ServerRequestScope()
		{
			in_server_request = false;
		}
	};

	// Everything a request handler needs, shared by the handlers of one server. The database is held weakly:
	// a running server doesn't keep a closed database alive, and a request that arrives while the database is
	// shutting down is answered with 503 instead of touching freed memory.
	struct ServeContext
	{
		weak_ptr<DatabaseInstance> db;
		std::string auth_token;
		bool basic_auth = false;
		// Unauthenticated loopback servers only answer requests whose Host header names a loopback address,
		// so a web page can't reach them through DNS rebinding.
		bool restrict_host = false;
		std::string bind_host;
		bool allow_any_origin = false;
		vector<std::string> allowed_origins;
	};

	// Base64 decoding function
	static std::string Base64Decode(const std::string &in)
	{
		std::string out;
		std::vector<int> T(256, -1);
		for (int i = 0; i < 64; i++)
			T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

		int val = 0, valb = -8;
		for (unsigned char c : in)
		{
			if (T[c] == -1)
				break;
			val = (val << 6) + T[c];
			valb += 6;
			if (valb >= 0)
			{
				out.push_back(char((val >> valb) & 0xFF));
				valb -= 8;
			}
		}
		return out;
	}

	// Compares two strings in time that depends only on their lengths, so response timing doesn't reveal
	// how much of a guessed credential is correct.
	static bool ConstantTimeEquals(const std::string &a, const std::string &b)
	{
		if (a.size() != b.size())
		{
			return false;
		}
		unsigned char diff = 0;
		for (size_t i = 0; i < a.size(); i++)
		{
			diff |= static_cast<unsigned char>(a[i] ^ b[i]);
		}
		return diff == 0;
	}

	static bool IsAuthenticated(const ServeContext &ctx, const HttpRequest &req)
	{
		if (ctx.auth_token.empty())
		{
			return true; // No authentication required if no token is set
		}

		// Each mode accepts only its own header, so a user:password server can't be reached with an
		// X-API-Key header, and a key server can't be reached with Basic auth.
		if (!ctx.basic_auth)
		{
			auto api_key = req.get_header_value("X-API-Key");
			return !api_key.empty() && ConstantTimeEquals(api_key, ctx.auth_token);
		}

		auto auth = req.get_header_value("Authorization");
		if (!auth.empty() && auth.compare(0, 6, "Basic ") == 0)
		{
			std::string decoded_auth = Base64Decode(auth.substr(6));
			return ConstantTimeEquals(decoded_auth, ctx.auth_token);
		}

		return false;
	}

	// Strips brackets from an IPv6 literal, so "[::1]" and "::1" compare equal.
	static std::string StripBrackets(const std::string &host)
	{
		if (host.size() >= 2 && host.front() == '[' && host.back() == ']')
		{
			return host.substr(1, host.size() - 2);
		}
		return host;
	}

	static bool IsLoopbackHost(const std::string &host_p)
	{
		auto host = StringUtil::Lower(StripBrackets(host_p));
		if (host == "localhost" || host == "::1")
		{
			return true;
		}
		// 127.0.0.0/8, written as a dotted IPv4 address (not a host name such as 127.example.com)
		if (!StringUtil::StartsWith(host, "127."))
		{
			return false;
		}
		for (char c : host)
		{
			if (c != '.' && (c < '0' || c > '9'))
			{
				return false;
			}
		}
		return true;
	}

	// The host name of a Host header, without the port.
	static std::string HostHeaderName(const std::string &header)
	{
		if (!header.empty() && header.front() == '[')
		{
			auto end = header.find(']');
			return end == std::string::npos ? header : header.substr(0, end + 1);
		}
		auto colon = header.find(':');
		return colon == std::string::npos ? header : header.substr(0, colon);
	}

	static bool IsAllowedHostHeader(const ServeContext &ctx, const HttpRequest &req)
	{
		if (!ctx.restrict_host)
		{
			return true;
		}
		auto header = req.get_header_value("Host");
		if (header.empty())
		{
			return true; // HTTP/1.0 clients; browsers always send Host
		}
		auto name = StringUtil::Lower(StripBrackets(HostHeaderName(header)));
		return IsLoopbackHost(name) || name == StringUtil::Lower(StripBrackets(ctx.bind_host));
	}

	enum class OriginDecision
	{
		// Not a cross-origin browser request (no Origin, or the page was served by this server)
		SAME_ORIGIN,
		// A cross-origin request from an origin listed in httpserver_allowed_origins
		ALLOWED,
		// A cross-origin browser request that must not run
		FORBIDDEN
	};

	static OriginDecision CheckOrigin(const ServeContext &ctx, const HttpRequest &req)
	{
		auto origin = req.get_header_value("Origin");
		if (origin.empty())
		{
			// Browsers omit Origin on simple GETs (e.g. <img src>), but label them with Sec-Fetch-Site.
			auto site = req.get_header_value("Sec-Fetch-Site");
			if ((site == "cross-site" || site == "same-site") && !ctx.allow_any_origin)
			{
				return OriginDecision::FORBIDDEN;
			}
			return OriginDecision::SAME_ORIGIN;
		}
		auto host = req.get_header_value("Host");
		if (!host.empty() && (origin == "http://" + host || origin == "https://" + host))
		{
			return OriginDecision::SAME_ORIGIN;
		}
		if (ctx.allow_any_origin)
		{
			return OriginDecision::ALLOWED;
		}
		for (auto &allowed : ctx.allowed_origins)
		{
			if (origin == allowed)
			{
				return OriginDecision::ALLOWED;
			}
		}
		return OriginDecision::FORBIDDEN;
	}

	// CORS headers are sent only to origins listed in httpserver_allowed_origins. Allow-Credentials is never
	// sent: browsers don't attach cookies or cached Basic auth, clients set the auth header explicitly.
	static void SetCorsHeaders(const ServeContext &ctx, const HttpRequest &req, HttpResponse &res,
														 const char *methods)
	{
		if (CheckOrigin(ctx, req) != OriginDecision::ALLOWED)
		{
			return;
		}
		res.set_header("Access-Control-Allow-Origin", ctx.allow_any_origin ? "*" : req.get_header_value("Origin"));
		if (!ctx.allow_any_origin)
		{
			res.set_header("Vary", "Origin");
		}
		res.set_header("Access-Control-Allow-Methods", methods);
		// A "*" in Allow-Headers does not cover Authorization, so it is listed explicitly.
		res.set_header("Access-Control-Allow-Headers",
									 "*, Authorization, X-API-Key, Content-Type, X-ClickHouse-Format, format");
		res.set_header("Access-Control-Max-Age", "86400");
	}

	// Rejects requests a browser was tricked into sending. Returns false (and fills the response) to stop.
	static bool AdmitRequest(const ServeContext &ctx, const HttpRequest &req, HttpResponse &res)
	{
		if (!IsAllowedHostHeader(ctx, req))
		{
			res.status = 403;
			res.set_content("Forbidden: this unauthenticated server only answers requests addressed to a loopback host",
											"text/plain");
			return false;
		}
		if (CheckOrigin(ctx, req) == OriginDecision::FORBIDDEN)
		{
			res.status = 403;
			res.set_content("Forbidden: cross-origin requests from this origin are not allowed (see the "
											"httpserver_allowed_origins setting)",
											"text/plain");
			return false;
		}
		return true;
	}

	static std::string ConvertResultToCSV(QueryResult &result)
	{
		std::string csv_output;

		// Add header row
		for (idx_t col = 0; col < result.ColumnCount(); ++col)
		{
			if (col > 0)
			{
				csv_output += ",";
			}
			csv_output += result.ColumnName(col).GetIdentifierName();
		}
		csv_output += "\n";

		// Add data rows
		auto &collection = result.Collection();
		for (auto &row : collection.Rows())
		{
			for (idx_t col = 0; col < result.ColumnCount(); ++col)
			{
				if (col > 0)
				{
					csv_output += ",";
				}
				Value value = row.GetValue(col);
				if (value.IsNull())
				{
					// Leave empty for NULL values
					continue;
				}

				std::string value_str = value.ToString();
				// Escape quotes and wrap in quotes if contains special characters
				if (value_str.find_first_of(",\"\n\r") != std::string::npos)
				{
					std::string escaped;
					escaped.reserve(value_str.length() + 2);
					escaped += '"';
					for (char c : value_str)
					{
						if (c == '"')
						{
							escaped += '"'; // Double the quotes to escape
						}
						escaped += c;
					}
					escaped += '"';
					csv_output += escaped;
				}
				else
				{
					csv_output += value_str;
				}
			}
			csv_output += "\n";
		}

		return csv_output;
	}

	static std::string EscapeXML(const std::string &in)
	{
		std::string out;
		out.reserve(in.size());
		for (char c : in)
		{
			switch (c)
			{
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

	static std::string ConvertResultToXML(QueryResult &result)
	{
		std::string xml;
		xml += "<results>\n";

		auto &collection = result.Collection();
		for (auto &row : collection.Rows())
		{
			xml += "  <row>\n";

			for (idx_t col = 0; col < result.ColumnCount(); ++col)
			{
				const std::string &col_name = result.ColumnName(col).GetIdentifierName(); // keep original
				Value val = row.GetValue(col);

				xml += "    <column name=\"";
				xml += EscapeXML(col_name);
				xml += "\">";

				if (!val.IsNull())
				{
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
	static void HandleHttpRequest(const ServeContext &ctx, const HttpRequest &req, HttpResponse &res)
	{
		// Declared first so it outlives the connection and database references below.
		ServerRequestScope request_scope;

		if (!AdmitRequest(ctx, req, res))
		{
			return;
		}
		SetCorsHeaders(ctx, req, res, "GET, POST, OPTIONS");

		if (!IsAuthenticated(ctx, req))
		{
			res.status = 401;
			if (ctx.basic_auth)
			{
				res.set_header("WWW-Authenticate", "Basic realm=\"DuckDB\", charset=\"UTF-8\"");
			}
			res.set_content("Unauthorized", "text/plain");
			return;
		}

		std::string query;
		// Check if the query is in the URL parameters
		if (req.has_param("query"))
		{
			query = req.get_param_value("query");
		}
		else if (req.has_param("q"))
		{
			query = req.get_param_value("q");
		}
		// If not in URL, and it's a POST request, check the body
		else if (req.method == "POST" && !req.body.empty())
		{
			query = req.body;
		}
		// Without a query, serve the playground page
		else
		{
			res.status = 200;
			res.set_content(reinterpret_cast<char const *>(playgroundContent), "text/html");
			return;
		}

		// Set default format to JSONEachRow
		std::string format = "JSONEachRow";

		// Check for format in URL parameter or header
		if (req.has_param("default_format"))
		{
			format = req.get_param_value("default_format");
		}
		else if (req.has_header("X-ClickHouse-Format"))
		{
			format = req.get_header_value("X-ClickHouse-Format");
		}
		else if (req.has_header("format"))
		{
			format = req.get_header_value("format");
		}

		try
		{
			auto db = ctx.db.lock();
			if (!db)
			{
				res.status = 503;
				res.set_content("The database is shutting down", "text/plain");
				return;
			}

			Connection con(*db);
			con.context->registered_state->Insert(ServedConnectionMarker::KEY,
			                                      make_shared_ptr<ServedConnectionMarker>());
			auto start = std::chrono::system_clock::now();
			auto result = con.Query(query);
			auto end = std::chrono::system_clock::now();
			auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

			if (result->HasError())
			{
				res.status = 500;
				res.set_content(result->GetError(), "text/plain");
				return;
			}

			ReqStats stats{static_cast<float>(elapsed.count()) / 1000, 0, 0};

			// Format Options
			if (format == "JSONCompact")
			{
				ResultSerializerCompactJson serializer;
				res.set_content(serializer.Serialize(*result, stats), "application/json");
			}
			else if (format == "CSV")
			{
				res.set_content(ConvertResultToCSV(*result), "text/csv");
			}
			else if (format == "XML")
			{
				res.set_content(ConvertResultToXML(*result), "application/xml");
			}
			else
			{
				// JSONEachRow, and the default for unknown formats
				ResultSerializerJsonEachRow serializer;
				res.set_content(serializer.Serialize(*result), "application/x-ndjson");
			}
		}
		catch (const std::exception &ex)
		{
			// Includes std::bad_weak_ptr from a connection opened while the database shuts down.
			ErrorData error(ex);
			res.status = 500;
			res.set_content("DB::Exception: " + error.Message(), "text/plain");
		}
	}

	// The server in foreground mode, stopped by SIGINT. Server::stop() only swaps an atomic and closes a socket,
	// which is safe from a signal handler.
	static std::atomic<HttpServer *> foreground_server{nullptr};

#ifndef _WIN32
	static void ForegroundSigintHandler(int)
	{
		auto server = foreground_server.load();
		if (server)
		{
			server->stop();
		}
	}
#endif

	static void ConfigureLogging(HttpServer &server)
	{
#ifndef _WIN32
		const char *debug_env = std::getenv("DUCKDB_HTTPSERVER_DEBUG");
		const char *use_syslog = std::getenv("DUCKDB_HTTPSERVER_SYSLOG");

		if (debug_env != nullptr && std::string(debug_env) == "1")
		{
			server.set_logger(
					[](const HttpRequest &req, const HttpResponse &res)
					{
						// Get current time with timezone offset
						time_t now_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
						struct tm tm_info;
						localtime_r(&now_time, &tm_info);
						char timestr[32];
						char timezone[8];
						strftime(timestr, sizeof(timestr), "%d/%b/%Y:%H:%M:%S", &tm_info);
						strftime(timezone, sizeof(timezone), "%z", &tm_info);

						std::string user_agent = req.has_header("User-Agent") ? req.get_header_value("User-Agent") : "-";
						std::string referer = req.has_header("Referer") ? req.get_header_value("Referer") : "-";
						std::string forwarded_for =
								req.has_header("X-Forwarded-For") ? req.get_header_value("X-Forwarded-For") : "-";
						fprintf(stdout, "%s - - [%s %s] \"%s %s HTTP/%s\" %d %zu \"%s\" \"%s\" \"%s\"\r\n",
										req.remote_addr.c_str(), timestr, timezone, req.method.c_str(), req.path.c_str(),
										req.version.c_str(), res.status, res.body.size(), referer.c_str(), user_agent.c_str(),
										forwarded_for.c_str());
						fflush(stdout);
					});
		}
		else if (use_syslog != nullptr && std::string(use_syslog) == "1")
		{
			static std::once_flag syslog_opened;
			std::call_once(syslog_opened, []()
										 {
				openlog("duckdb-httpserver", LOG_PID | LOG_NDELAY, LOG_LOCAL0);
				std::atexit([]() { closelog(); }); });
			server.set_logger(
					[](const HttpRequest &req, const HttpResponse &res)
					{
						std::string user_agent = req.has_header("User-Agent") ? req.get_header_value("User-Agent") : "-";
						std::string referer = req.has_header("Referer") ? req.get_header_value("Referer") : "-";
						std::string forwarded_for =
								req.has_header("X-Forwarded-For") ? req.get_header_value("X-Forwarded-For") : "-";

						syslog(LOG_INFO, "%s - - \"%s %s HTTP/%s\" %d %zu \"%s\" \"%s\" \"%s\"", req.remote_addr.c_str(),
									 req.method.c_str(), req.path.c_str(), req.version.c_str(), res.status, res.body.size(),
									 referer.c_str(), user_agent.c_str(), forwarded_for.c_str());
					});
		}
#endif
	}

	template <class T>
	static T GetSetting(ClientContext &context, const char *name, T default_value)
	{
		Value value;
		if (context.TryGetCurrentSetting(name, value) && !value.IsNull())
		{
			return value.GetValue<T>();
		}
		return default_value;
	}

	// The HTTP server of one database. It lives in the database's object cache, so it is stopped when the
	// database shuts down, and each database can serve on its own port.
	class HttpServerInstance : public ObjectCacheEntry
	{
	public:
		HttpServerInstance()
		{
		}

		~HttpServerInstance() override
		{
			std::lock_guard<std::mutex> guard(lock);
			if (!server)
			{
				return;
			}
			server->stop();
			if (foreground)
			{
				// Unreachable in practice: the foreground caller holds a reference to the database.
				(void)server.release();
				return;
			}
			if (in_server_request)
			{
				// The database's last reference was dropped by a request, so this runs on one of the server's
				// own threads, which the listener would join. Let the listener wind down on its own.
				if (server_thread)
				{
					server_thread->detach();
				}
				(void)server.release();
				return;
			}
			if (server_thread && server_thread->joinable())
			{
				server_thread->join();
			}
		}

		static string ObjectType()
		{
			return "httpserver_instance";
		}

		string GetObjectType() override
		{
			return ObjectType();
		}

		optional_idx GetEstimatedCacheMemory() const override
		{
			return optional_idx(); // never evicted
		}

		static HttpServerInstance &Get(DatabaseInstance &db)
		{
			auto instance = db.GetObjectCache().GetOrCreate<HttpServerInstance>(ObjectType());
			if (!instance)
			{
				throw InternalException("Could not initialize the HTTP server state of this database");
			}
			return *instance;
		}

		std::string Start(ClientContext &context, const std::string &host, int64_t port, const std::string &auth)
		{
			if (!Settings::Get<EnableExternalAccessSetting>(context))
			{
				throw PermissionException("httpserve_start is disabled because enable_external_access is false");
			}
			if (port < 0 || port > 65535)
			{
				throw InvalidInputException("httpserve_start: port must be between 0 and 65535, got %d", port);
			}

			auto allow_unauthenticated_remote = GetSetting<bool>(context, ALLOW_UNAUTHENTICATED_REMOTE_SETTING, false);
			if (auth.empty() && !IsLoopbackHost(host) && !allow_unauthenticated_remote)
			{
				throw PermissionException(
						"httpserve_start: refusing to serve %s without authentication, anyone who can reach it could run "
						"any SQL. Pass an auth credential, bind to a loopback address such as 127.0.0.1, or SET %s = true",
						host, ALLOW_UNAUTHENTICATED_REMOTE_SETTING);
			}

			auto ctx = make_shared_ptr<ServeContext>();
			ctx->db = DatabaseInstance::GetDatabase(context).shared_from_this();
			ctx->auth_token = auth;
			ctx->basic_auth = auth.find(':') != std::string::npos;
			ctx->bind_host = host;
			ctx->restrict_host = auth.empty() && IsLoopbackHost(host);
			for (auto &origin : StringUtil::Split(GetSetting<string>(context, ALLOWED_ORIGINS_SETTING, ""), ','))
			{
				auto trimmed = origin;
				StringUtil::Trim(trimmed);
				if (trimmed == "*")
				{
					ctx->allow_any_origin = true;
				}
				else if (!trimmed.empty())
				{
					ctx->allowed_origins.push_back(trimmed);
				}
			}

			auto tls_cert = GetSetting<string>(context, TLS_CERT_SETTING, "");
			auto tls_key = GetSetting<string>(context, TLS_KEY_SETTING, "");
			if (tls_cert.empty() != tls_key.empty())
			{
				throw InvalidInputException("httpserve_start: TLS needs both %s and %s to be set", TLS_CERT_SETTING,
																		TLS_KEY_SETTING);
			}
			bool use_tls = !tls_cert.empty();

			const char *run_in_same_thread_env = std::getenv("DUCKDB_HTTPSERVER_FOREGROUND");
			bool run_in_same_thread = (run_in_same_thread_env != nullptr && std::string(run_in_same_thread_env) == "1");
#ifdef _WIN32
			if (run_in_same_thread)
			{
				throw IOException("Foreground mode not yet supported on WIN32 platforms.");
			}
#endif

			std::unique_lock<std::mutex> guard(lock);
			if (server)
			{
				if (foreground || server->is_running())
				{
					throw InvalidInputException("HTTP server is already running");
				}
				// The listener exited on its own (listen failed after binding): clean it up before restarting.
				ResetLocked();
			}

			unique_ptr<HttpServer> new_server;
			if (use_tls)
			{
				auto tls_server = make_uniq<duckdb_httplib_openssl::SSLServer>(tls_cert.c_str(), tls_key.c_str());
				if (!tls_server->is_valid())
				{
					throw IOException("httpserve_start: could not load the TLS certificate '%s' and private key '%s'",
														tls_cert, tls_key);
				}
				new_server = std::move(tls_server);
			}
			else
			{
				new_server = make_uniq<HttpServer>();
			}

			// Custom basepath, defaults to root /
			const char *base_path_env = std::getenv("DUCKDB_HTTPSERVER_BASEPATH");
			std::string base_path = "/";
			if (base_path_env && base_path_env[0] == '/' && strlen(base_path_env) > 1)
			{
				base_path = std::string(base_path_env);
				// Ensure trailing slash for consistent endpoint joining
				if (base_path.back() != '/')
				{
					base_path += '/';
				}
			}

			// CORS preflight - no authentication required for OPTIONS requests
			new_server->Options(base_path, [ctx](const HttpRequest &req, HttpResponse &res)
													{
				SetCorsHeaders(*ctx, req, res, "GET, POST, OPTIONS");
				res.status = CheckOrigin(*ctx, req) == OriginDecision::FORBIDDEN ? 403 : 204; });

			auto handler = [ctx](const HttpRequest &req, HttpResponse &res)
			{ HandleHttpRequest(*ctx, req, res); };
			new_server->Get(base_path, handler);
			new_server->Post(base_path, handler);

			// Health check endpoint - no authentication required
			new_server->Get(base_path + "ping", [ctx](const HttpRequest &req, HttpResponse &res)
											{
				if (!AdmitRequest(*ctx, req, res)) {
					return;
				}
				SetCorsHeaders(*ctx, req, res, "GET, OPTIONS");
				res.set_content("OK", "text/plain"); });

			ConfigureLogging(*new_server);

			// httplib's default sets SO_REUSEPORT, which lets a second server bind a port that is already
			// listening and silently take a share of its connections. Only allow rebinding over TIME_WAIT.
			new_server->set_socket_options([](socket_t sock)
																		 {
#ifdef _WIN32
				duckdb_httplib_openssl::set_socket_opt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1);
#else
				duckdb_httplib_openssl::set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
#endif
																		 });

			// Bind on the calling thread, so a port that is in use or a bad host is reported as an error from
			// httpserve_start. An exception escaping the listener thread would terminate the whole process.
			int bound_port;
			if (port == 0)
			{
				bound_port = new_server->bind_to_any_port(host);
			}
			else
			{
				bound_port = new_server->bind_to_port(host, static_cast<int>(port)) ? static_cast<int>(port) : -1;
			}
			if (bound_port <= 0)
			{
				throw IOException("Failed to start HTTP server on " + host + ":" + std::to_string(port) +
													": the address could not be bound (is the port already in use?)");
			}

			std::string started = std::string(use_tls ? "HTTPS" : "HTTP") + " server started on " + host + ":" +
														std::to_string(bound_port);
			server = std::move(new_server);

			if (run_in_same_thread)
			{
#ifndef _WIN32
				foreground = true;
				auto *listening = server.get();
				guard.unlock();

				foreground_server = listening;
				auto previous_handler = signal(SIGINT, ForegroundSigintHandler);
				listening->listen_after_bind();
				signal(SIGINT, previous_handler);
				foreground_server = nullptr;

				guard.lock();
				foreground = false;
				server.reset();
#endif
				return started;
			}

			// Run the server in a dedicated thread (default). It never throws: a listen that fails after binding
			// just ends the thread, and the next start cleans up.
			auto *listening = server.get();
			server_thread = make_uniq<std::thread>([listening]()
																						 { listening->listen_after_bind(); });

			// Return only once the accept loop is running. Some httplib versions ignore a stop() that arrives
			// before then, which would leave httpserve_stop() waiting forever on a listener that never ends.
			// This also reports a listen that fails after binding.
			server->wait_until_ready();
			if (!server->is_running())
			{
				ResetLocked();
				throw IOException("Failed to start HTTP server on " + host + ":" + std::to_string(bound_port));
			}
			return started;
		}

		void Stop(ClientContext &context)
		{
			if (in_server_request || context.registered_state->Get<ServedConnectionMarker>(ServedConnectionMarker::KEY))
			{
				throw InvalidInputException(
						"httpserve_stop() can't be called from a query that the HTTP server itself is serving");
			}
			unique_ptr<HttpServer> stopping;
			unique_ptr<std::thread> listener;
			{
				std::lock_guard<std::mutex> guard(lock);
				if (!server)
				{
					return;
				}
				if (foreground)
				{
					// The foreground caller cleans up once its listen returns.
					server->stop();
					return;
				}
				stopping = std::move(server);
				listener = std::move(server_thread);
			}
			stopping->stop();
			if (listener && listener->joinable())
			{
				listener->join();
			}
		}

	private:
		// Stops and joins the server; the caller holds the lock.
		void ResetLocked()
		{
			if (server)
			{
				server->stop();
			}
			if (server_thread && server_thread->joinable())
			{
				server_thread->join();
			}
			server_thread.reset();
			server.reset();
		}

		std::mutex lock;
		unique_ptr<HttpServer> server;
		unique_ptr<std::thread> server_thread;
		bool foreground = false;
	};

	static void HttpServeStartFunction(DataChunk &args, ExpressionState &state, Vector &result)
	{
		auto &context = state.GetContext();
		auto &instance = HttpServerInstance::Get(DatabaseInstance::GetDatabase(context));
		for (idx_t row = 0; row < args.size(); row++)
		{
			auto host_value = args.data[0].GetValue(row);
			if (host_value.IsNull())
			{
				result.SetValue(row, Value(LogicalType::VARCHAR));
				continue;
			}
			auto port_value = args.data[1].GetValue(row);
			auto auth_value = args.data[2].GetValue(row);
			int64_t port = port_value.IsNull() ? 0 : port_value.GetValue<int64_t>();
			std::string auth = auth_value.IsNull() ? std::string() : auth_value.ToString();
			result.SetValue(row, Value(instance.Start(context, host_value.ToString(), port, auth)));
		}
	}

	static void HttpServeStopFunction(DataChunk &args, ExpressionState &state, Vector &result)
	{
		auto &context = state.GetContext();
		HttpServerInstance::Get(DatabaseInstance::GetDatabase(context)).Stop(context);
		result.SetVectorType(VectorType::CONSTANT_VECTOR);
		result.SetValue(0, Value("HTTP server stopped"));
	}

	// Declares a positional-only parameter with a real name, so duckdb_functions() reports it instead of col<N>.
	static FunctionParameter Positional(const char *name, LogicalType type)
	{
		return FunctionParameter(name, std::move(type), {}, FunctionParameterKind::POSITIONAL_ONLY);
	}

	static void LoadInternal(ExtensionLoader &loader)
	{
		auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
		config.AddExtensionOption(ALLOWED_ORIGINS_SETTING,
															"Comma-separated origins (e.g. https://app.example.com) whose web pages may call the "
															"HTTP server, or * for any. Other cross-origin browser requests are refused. Read by "
															"httpserve_start.",
															LogicalType::VARCHAR, Value(""));
		config.AddExtensionOption(ALLOW_UNAUTHENTICATED_REMOTE_SETTING,
															"Allow httpserve_start to listen on a non-loopback address without an auth credential, "
															"letting anyone who can reach it run any SQL.",
															LogicalType::BOOLEAN, Value::BOOLEAN(false));
		config.AddExtensionOption(TLS_CERT_SETTING,
															"Path to a PEM certificate (chain); with httpserver_tls_key set, httpserve_start serves "
															"HTTPS.",
															LogicalType::VARCHAR, Value(""));
		config.AddExtensionOption(TLS_KEY_SETTING,
															"Path to the PEM private key for httpserver_tls_cert.", LogicalType::VARCHAR, Value(""));

		auto httpserve_start = ScalarFunction(
				"httpserve_start",
				{Positional("host", LogicalType::VARCHAR), Positional("port", LogicalType::INTEGER),
				 Positional("auth", LogicalType::VARCHAR)},
				LogicalType::VARCHAR, HttpServeStartFunction);
		httpserve_start.SetVolatile();
		httpserve_start.SetFallible();
		httpserve_start.SetNullHandling(FunctionNullHandling::SPECIAL_HANDLING);

		CreateScalarFunctionInfo start_info(httpserve_start);
		start_info.descriptions.push_back(
				{{LogicalType::VARCHAR, LogicalType::INTEGER, LogicalType::VARCHAR},
				 {"host", "port", "auth"},
				 "Starts an HTTP server for this database that runs SQL sent in GET/POST requests and returns "
				 "JSONEachRow, JSONCompact, CSV or XML. Port 0 picks a free port. auth is an X-API-Key value, or "
				 "user:password for HTTP Basic auth; an empty auth is only allowed on loopback addresses unless "
				 "httpserver_allow_unauthenticated_remote is set. Refused when enable_external_access is false.",
				 {"httpserve_start('127.0.0.1', 8080, '')", "httpserve_start('0.0.0.0', 8080, 'user:s3cret')"},
				 {"network", "server"}});
		loader.RegisterFunction(start_info);

		auto httpserve_stop = ScalarFunction("httpserve_stop", {}, LogicalType::VARCHAR, HttpServeStopFunction);
		httpserve_stop.SetVolatile();
		httpserve_stop.SetFallible();
		CreateScalarFunctionInfo stop_info(httpserve_stop);
		stop_info.descriptions.push_back({{},
																			{},
																			"Stops this database's HTTP server, waiting for in-flight requests. Does "
																			"nothing when no server is running.",
																			{"httpserve_stop()"},
																			{"network", "server"}});
		loader.RegisterFunction(stop_info);

		QueryFarmSendTelemetry(loader, "httpserver", HTTPSERVER_VERSION);
	}

	void HttpserverExtension::Load(ExtensionLoader &loader)
	{
		LoadInternal(loader);
	}

	std::string HttpserverExtension::Name()
	{
		return "httpserver";
	}

	std::string HttpserverExtension::Version() const
	{
		return HTTPSERVER_VERSION;
	}

} // namespace duckdb

extern "C"
{
	DUCKDB_CPP_EXTENSION_ENTRY(httpserver, loader)
	{
		duckdb::LoadInternal(loader);
	}
}
