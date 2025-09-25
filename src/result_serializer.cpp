#include "result_serializer.hpp"

#include "duckdb/common/extra_type_info.hpp"
#include "duckdb/common/types/uuid.hpp"

#include <cmath>

namespace duckdb {

#define YY_APPEND_FAIL(success)                                                                                        \
	if (!success) {                                                                                                    \
		throw SerializationException("Failed to append in " __FILE__, __LINE__);                                       \
	}

void ResultSerializer::SerializeInternal(QueryResult &query_result, yyjson_mut_val *append_root,
                                         const bool values_as_array) {
	auto chunk = query_result.Fetch();
	auto names = query_result.names;
	auto types = query_result.types;

	while (chunk) {
		SerializeChunk(*chunk, names, types, append_root, values_as_array);
		chunk = query_result.Fetch();
	}
}

void ResultSerializer::SerializeChunk(const DataChunk &chunk, vector<string> &names, vector<LogicalType> &types,
                                      yyjson_mut_val *append_root, const bool values_as_array) {
	D_ASSERT(yyjson_mut_is_arr(append_root));

	const auto row_count = chunk.size();

	for (idx_t row_idx = 0; row_idx < row_count; row_idx++) {

		// Which itself contains an object
		yyjson_mut_val *obj;

		if (values_as_array) {
			obj = SerializeRowAsArray(chunk, row_idx, types);
		} else {
			obj = SerializeRowAsObject(chunk, row_idx, names, types);
		}

		YY_APPEND_FAIL(yyjson_mut_arr_append(append_root, obj));
	}
}

yyjson_mut_val *ResultSerializer::SerializeRowAsArray(const DataChunk &chunk, const idx_t row_idx,
                                                      vector<LogicalType> &types) {
	const auto column_count = chunk.ColumnCount();
	auto obj = yyjson_mut_arr(doc);

	for (idx_t col_idx = 0; col_idx < column_count; col_idx++) {
		auto value = chunk.GetValue(col_idx, row_idx);
		auto &type = types[col_idx];
		SerializeValue(obj, value, nullptr, type);
	}

	return obj;
}

yyjson_mut_val *ResultSerializer::SerializeRowAsObject(const DataChunk &chunk, const idx_t row_idx,
                                                       vector<string> &names, vector<LogicalType> &types) {
	const auto column_count = chunk.ColumnCount();
	auto obj = yyjson_mut_obj(doc);

	for (idx_t col_idx = 0; col_idx < column_count; col_idx++) {
		auto value = chunk.GetValue(col_idx, row_idx);
		auto &type = types[col_idx];
		SerializeValue(obj, value, names[col_idx], type);
	}

	return obj;
}

void ResultSerializer::SerializeValue( // NOLINT(*-no-recursion)
    yyjson_mut_val *parent, const Value &value, optional_ptr<string> name, const LogicalType &type) {
	yyjson_mut_val *val = nullptr;

	if (value.IsNull()) {
		goto null_handle;
	}

	switch (type.id()) {
	case LogicalTypeId::SQLNULL:
	null_handle:
		val = yyjson_mut_null(doc);
		break;
	case LogicalTypeId::BOOLEAN:
		val = yyjson_mut_bool(doc, value.GetValue<bool>());
		break;
	case LogicalTypeId::TINYINT:
	case LogicalTypeId::SMALLINT:
	case LogicalTypeId::INTEGER:
	case LogicalTypeId::BIGINT:
	case LogicalTypeId::INTEGER_LITERAL:
		val = yyjson_mut_int(doc, value.GetValue<int64_t>());
		break;
	case LogicalTypeId::UTINYINT:
	case LogicalTypeId::USMALLINT:
	case LogicalTypeId::UINTEGER:
	case LogicalTypeId::UBIGINT:
		val = yyjson_mut_uint(doc, value.GetValue<uint64_t>());
		break;

	// format to big numbers as strings
	case LogicalTypeId::UHUGEINT: {
		const uhugeint_t uHugeIntNumber = value.GetValue<uhugeint_t>();
		val = yyjson_mut_strcpy(doc, uHugeIntNumber.ToString().c_str());
		break;
	}
	case LogicalTypeId::HUGEINT: {
		const hugeint_t hugeIntNumber = value.GetValue<hugeint_t>();
		val = yyjson_mut_strcpy(doc, hugeIntNumber.ToString().c_str());
		break;
	}

	case LogicalTypeId::FLOAT:
	case LogicalTypeId::DOUBLE:
	case LogicalTypeId::DECIMAL: {
		const auto real_val = value.GetValue<double>();
		if (std::isnan(real_val) || std::isinf(real_val)) {
			if (set_invalid_values_to_null) {
				goto null_handle;
			} else {
				const auto castedValue = value.DefaultCastAs(LogicalTypeId::VARCHAR).GetValue<string>();
				val = yyjson_mut_strcpy(doc, castedValue.c_str());
				break;
			}
		} else {
			val = yyjson_mut_real(doc, real_val);
			break;
		}
	}
		// Data + time
	case LogicalTypeId::DATE:
	case LogicalTypeId::TIME:
	case LogicalTypeId::TIMESTAMP_SEC:
	case LogicalTypeId::TIMESTAMP_MS:
	case LogicalTypeId::TIMESTAMP:
	case LogicalTypeId::TIMESTAMP_NS:
	case LogicalTypeId::TIMESTAMP_TZ:
	case LogicalTypeId::TIME_TZ:
	case LogicalTypeId::TIME_NS:
		// Enum
	case LogicalTypeId::ENUM:
		// Strings
	case LogicalTypeId::CHAR:
	case LogicalTypeId::VARCHAR:
	case LogicalTypeId::STRING_LITERAL:
		val = yyjson_mut_strcpy(doc, value.GetValue<string>().c_str());
		break;
	case LogicalTypeId::BIGNUM:
		val = yyjson_mut_strcpy(doc, value.DefaultCastAs(LogicalTypeId::VARCHAR).GetValue<string>().c_str());
		break;
		// UUID
	case LogicalTypeId::UUID: {
		const auto uuid_int = value.GetValue<hugeint_t>();
		const auto uuid = UUID::ToString(uuid_int);
		val = yyjson_mut_strcpy(doc, uuid.c_str());
		break;
	}
		// Weird special types that are just serialized to string
	case LogicalTypeId::INTERVAL:
		// TODO perhaps base64 encode blob?
	case LogicalTypeId::BLOB:
	case LogicalTypeId::BIT:
		val = yyjson_mut_strcpy(doc, value.ToString().c_str());
		break;
	case LogicalTypeId::UNION: {
		auto &union_val = UnionValue::GetValue(value);
		SerializeValue(parent, union_val, name, union_val.type());
		return;
	}
	case LogicalTypeId::ARRAY:
	case LogicalTypeId::LIST: {
		const auto get_children = LogicalTypeId::LIST == type.id() ? ListValue::GetChildren : ArrayValue::GetChildren;
		auto &children = get_children(value);
		val = yyjson_mut_arr(doc);
		for (auto &child : children) {
			SerializeValue(val, child, nullptr, child.type());
		}
		break;
	}
	case LogicalTypeId::STRUCT: {
		const auto &children = StructValue::GetChildren(value);
		const auto &type_info = value.type().AuxInfo()->Cast<StructTypeInfo>();

		auto all_keys_are_empty = true;
		for (uint64_t idx = 0; idx < children.size(); ++idx) {
			if (!type_info.child_types[idx].first.empty()) {
				all_keys_are_empty = false;
				break;
			}
		}

		// Unnamed struct -> just create tuples
		if (all_keys_are_empty) {
			val = yyjson_mut_arr(doc);
			for (auto &child : children) {
				SerializeValue(val, child, nullptr, child.type());
			}
		} else {
			val = yyjson_mut_obj(doc);
			for (uint64_t idx = 0; idx < children.size(); ++idx) {
				string struct_name = type_info.child_types[idx].first;
				SerializeValue(val, children[idx], struct_name, type_info.child_types[idx].second);
			}
		}

		break;
	}
		// Not implemented types
	case LogicalTypeId::MAP: {
		auto &children = ListValue::GetChildren(value);
		val = yyjson_mut_obj(doc);
		for (auto &item : children) {
			auto &key_value = StructValue::GetChildren(item);
			D_ASSERT(key_value.size() == 2);
			auto key_str = key_value[0].GetValue<string>();
			SerializeValue(val, key_value[1], key_str, key_value[1].type());
		}
		break;
	}

	// Unsupported types
	case LogicalTypeId::TABLE:
	case LogicalTypeId::POINTER:
	case LogicalTypeId::VALIDITY:
	case LogicalTypeId::AGGREGATE_STATE:
	case LogicalTypeId::LAMBDA:
	case LogicalTypeId::USER:
	case LogicalTypeId::ANY:
	case LogicalTypeId::UNKNOWN:
	case LogicalTypeId::INVALID:
	case LogicalTypeId::TEMPLATE:
	case LogicalTypeId::VARIANT:
		if (set_invalid_values_to_null) {
			goto null_handle;
		}
		throw InvalidTypeException("Type " + type.ToString() + " not supported");
	}

	if (!val) {
		throw SerializationException("Could not serialize value of type " + type.ToString());
	}
	if (!name) {
		YY_APPEND_FAIL(yyjson_mut_arr_append(parent, val));
	} else {
		yyjson_mut_val *key = yyjson_mut_strcpy(doc, name->c_str());
		D_ASSERT(key);
		YY_APPEND_FAIL(yyjson_mut_obj_add(parent, key, val));
	}
}

} // namespace duckdb
