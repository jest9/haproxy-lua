--core.register_action("modify_set_cookie", { "http-req" }, function(txn)
    -- Add custom header to the request
--   txn.http:req_set_header("X-Custom-Header", "testreq")
--end)

--core.register_action("add_custom_header", { "http-res" }, function(txn)
    -- Add custom header to response
--    txn.http:res_set_header("X-Custom-Header", "testres")
--end)
core.register_action("uppercase_set_cookie", { "http-req" }, function(txn)
    -- get set-cookie header from response
    -- test : txn.http:res_set_header("X-Custom-Header", "testres")
    local set_cookie_headers = txn.http:req_get_headers()["cookie"][0]
    local upper_cookie_headers = string.upper(set_cookie_headers)
    txn.http:res_set_header("cookie", upper_cookie_headers)
end)


-- Function to uppercase Set-Cookie header value
core.register_action("lowercase_set_cookie", { "http-res" }, function(txn)
    -- get set-cookie header from response
    -- test : txn.http:res_set_header("X-Custom-Header", "testres")
    local set_cookie_headers = txn.http:res_get_headers()["set-cookie"][0]
    local lower_cookie_headers = string.upper(set_cookie_headers)
    txn.http:res_set_header("set-cookie", lower_cookie_headers)
end)

-- TODO:
-- change cookie such that:
-- upper case on entry from haproxy
-- lowercase on exit from haproxy
-- cookie, Set-Cookie