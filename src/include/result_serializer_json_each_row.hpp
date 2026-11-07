#pragma once
#include "result_serializer.hpp"

namespace duckdb {

// Newline-delimited JSON objects, one per row. Values keep their JSON types: numbers and booleans are not
// quoted, nested types become arrays and objects (as in JSONCompact). HUGEINT/UHUGEINT stay strings.
class ResultSerializerJsonEachRow final : public ResultSerializer {
public:
	explicit ResultSerializerJsonEachRow(const bool _set_invalid_values_to_null = false)
	    : ResultSerializer(_set_invalid_values_to_null) {
	}

	std::string Serialize(QueryResult &query_result) {
		vector<string> names;
		for (auto &name : query_result.GetNames()) {
			names.push_back(name.GetIdentifierName());
		}
		auto types = query_result.GetTypes();

		std::string output;
		auto chunk = query_result.Fetch();
		while (chunk) {
			for (idx_t row_idx = 0; row_idx < chunk->size(); row_idx++) {
				auto obj = SerializeRowAsObject(*chunk, row_idx, names, types);
				size_t length = 0;
				char *line = yyjson_mut_val_write(obj, 0, &length);
				if (!line) {
					throw SerializationException("Failed to render a row as JSON");
				}
				output.append(line, length);
				output += '\n';
				free(line);
			}
			// Start each chunk with a fresh document, so memory stays bounded by one chunk of values.
			yyjson_mut_doc_free(doc);
			doc = yyjson_mut_doc_new(nullptr);
			chunk = query_result.Fetch();
		}
		return output;
	}
};
} // namespace duckdb
