

core.register_action("uppercase_set_cookie", { "http-req" }, function(txn)
    -- get set-cookie header from response
    -- txn.http:req_set_header("X-Custom-Header", "testres")
    local set_cookie_headers = txn.http:req_get_headers()["cookie"][0]
    local upper_cookie_headers = string.upper(set_cookie_headers)
    txn.http:req_set_header("Cookie", set_cookie_headers)
    -- txn.http:req_set_header("testres", "yes")
end)


-- Function to uppercase Set-Cookie header value
core.register_action("lowercase_set_cookie", { "http-res" }, function(txn)
    -- get set-cookie header from response
    -- txn.http:res_set_header("X-Custom-Header", "testres")
    local set_cookie_headers = txn.http:res_get_headers()["set-cookie"][0]
    local lower_cookie_headers = string.lower(set_cookie_headers)
    txn.http:res_set_header("set-cookie", lower_cookie_headers)
end)

-- TODO:
-- change cookie such that:
-- upper case on entry from haproxy
-- lowercase on exit from haproxy
-- cookie, Set-Cookie