local openssl = require("openssl")

-- uppercase set cookie
core.register_action("uppercase_set_cookie", { "http-req" }, function(txn)
    local set_cookie_headers = txn.http:req_get_headers()["cookie"][0]
    local upper_cookie_headers = string.upper(set_cookie_headers)
    txn.http:req_set_header("Cookie", upper_cookie_headers)
end)

-- lowercase set cookie
core.register_action("lowercase_set_cookie", { "http-res" }, function(txn)
    local set_cookie_headers = txn.http:res_get_headers()["set-cookie"][0]
    local lower_cookie_headers = string.lower(set_cookie_headers)
    
    -- test block

    local test = openssl.version()
    txn.http:res_set_header("set-cookie", test)    

    -- txn.http:res_set_header("set-cookie", lower_cookie_headers)
end)

-- todo: encrypt cookies