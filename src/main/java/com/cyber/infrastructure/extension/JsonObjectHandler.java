package com.cyber.infrastructure.extension;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.apache.ibatis.type.BaseTypeHandler;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.MappedJdbcTypes;
import org.apache.ibatis.type.MappedTypes;

import java.sql.CallableStatement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;


@MappedTypes({JSONObject.class})
@MappedJdbcTypes(JdbcType.VARCHAR)
public class JsonObjectHandler extends BaseTypeHandler<JSONObject> {
    @Override
    public void setNonNullParameter(PreparedStatement preparedStatement, int i, JSONObject jsonObject, JdbcType jdbcType) throws SQLException {
        preparedStatement.setString(i, JSON.toJSONString(jsonObject));
    }

    @Override
    public JSONObject getNullableResult(ResultSet resultSet, String s) throws SQLException {
        return JSON.parseObject(resultSet.getString(s));
    }

    @Override
    public JSONObject getNullableResult(ResultSet resultSet, int i) throws SQLException {
        return JSON.parseObject(resultSet.getString(i));

    }

    @Override
    public JSONObject getNullableResult(CallableStatement callableStatement, int i) throws SQLException {
        return JSON.parseObject(callableStatement.getString(i));
    }
}
