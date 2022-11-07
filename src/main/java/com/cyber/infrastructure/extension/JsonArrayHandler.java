package com.cyber.infrastructure.extension;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import org.apache.ibatis.type.BaseTypeHandler;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.MappedJdbcTypes;
import org.apache.ibatis.type.MappedTypes;

import java.sql.CallableStatement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

@MappedTypes({JSONArray.class})
@MappedJdbcTypes(JdbcType.VARCHAR)
public class JsonArrayHandler extends BaseTypeHandler<JSONArray> {
    @Override
    public void setNonNullParameter(PreparedStatement preparedStatement, int i, JSONArray objects, JdbcType jdbcType) throws SQLException {
        preparedStatement.setString(i, JSON.toJSONString(objects));
    }

    @Override
    public JSONArray getNullableResult(ResultSet resultSet, String s) throws SQLException {
        return JSON.parseArray(resultSet.getString(s));
    }

    @Override
    public JSONArray getNullableResult(ResultSet resultSet, int i) throws SQLException {
        return JSON.parseArray(resultSet.getString(i));
    }

    @Override
    public JSONArray getNullableResult(CallableStatement callableStatement, int i) throws SQLException {
        return JSON.parseArray(callableStatement.getString(i));
    }
}
