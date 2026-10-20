#pragma once
#include "query_stats.hpp"
#include "result_serializer.hpp"

namespace duckdb {

class ResultSerializerCompactJson final : public ResultSerializer {
public:
	explicit ResultSerializerCompactJson(const bool _set_invalid_values_to_null = false)
	    : ResultSerializer(_set_invalid_values_to_null) {
		root = yyjson_mut_obj(doc);
		D_ASSERT(root);
		yyjson_mut_doc_set_root(doc, root);
	}

	std::string Serialize(QueryResult &query_result, const ReqStats &stats) {
		// Metadata about the query result
		yyjson_mut_val *yy_meta = GetMeta(query_result);
		yyjson_mut_obj_add_val(doc, root, "meta", yy_meta);

		// Actual query data
		yyjson_mut_val *yy_data_array = yyjson_mut_arr(doc);
		SerializeInternal(query_result, yy_data_array, true);
		yyjson_mut_obj_add_val(doc, root, "data", yy_data_array);

		// Number of rows
		yyjson_mut_obj_add_uint(doc, root, "rows", query_result.RowCount());

		// Query statistics
		yyjson_mut_val *yy_stats = GetStats(stats);
		yyjson_mut_obj_add_val(doc, root, "statistics", yy_stats);

		return YY_ToString();
	}

private:
	yyjson_mut_val *GetMeta(QueryResult &query_result) {
		auto meta_array = yyjson_mut_arr(doc);
		for (idx_t col = 0; col < query_result.ColumnCount(); ++col) {
			auto column_obj = yyjson_mut_obj(doc);
			yyjson_mut_obj_add_strcpy(doc, column_obj, "name", query_result.ColumnName(col).c_str());
			yyjson_mut_arr_append(meta_array, column_obj);
			// @paul Did you find out if result.RowCount() == 0 is needed?
			std::string tp(query_result.GetTypes()[col].ToString());
			yyjson_mut_obj_add_strcpy(doc, column_obj, "type", tp.c_str());
		}

		return meta_array;
	}

	yyjson_mut_val *GetStats(const ReqStats &stats) {
		auto stat_obj = yyjson_mut_obj(doc);
		yyjson_mut_obj_add_real(doc, stat_obj, "elapsed", stats.elapsed_sec);
		yyjson_mut_obj_add_int(doc, stat_obj, "rows_read", stats.read_rows);
		yyjson_mut_obj_add_int(doc, stat_obj, "bytes_read", stats.read_bytes);
		return stat_obj;
	}

	yyjson_mut_val *root;
};
} // namespace duckdb
