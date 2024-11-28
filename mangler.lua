local openssl = require("openssl")
local aes = require "openssl".aes
local sha256 = openssl.digest.new("sha256")

-- hashing

function hashing(ip)
    local secret = "iOoVXyufFCUqvSqCOkr2Nbu3wWfOuA82" -- any secret will do https://randomkeygen.com/
    local conc = secret .. ip
    sha256:update(conc)
    local hash = openssl.hex(sha256:final())
    local key = hash:sub(1, 64)
    local iv = hash:sub(65, 96)
    return key, iv
end

-- encryption logic














-- haproxy logic

core.register_action("encrypt_set_cookie", { "http-req" }, function(txn)
    local set_cookie_headers = txn.http:req_get_headers()["cookie"][0]
    local remote_addr = txn.sf:src()
    local key, iv = hashing(remote_addr)
    local upper_cookie_headers = string.upper(set_cookie_headers)
    --test block
    

    txn.http:req_set_header("Cookie", key)

    -- txn.http:req_set_header("Cookie", upper_cookie_headers)

end)

-- lowercase set cookie
core.register_action("decrypt_set_cookie", { "http-res" }, function(txn)
    local set_cookie_headers = txn.http:res_get_headers()["set-cookie"][0]
    local lower_cookie_headers = string.lower(set_cookie_headers)
    
    -- test block
    -- local test = openssl.version()
    txn.http:res_set_header("set-cookie", lower_cookie_headers)    

    -- txn.http:res_set_header("set-cookie", lower_cookie_headers)
end)


-- todo: encrypt cookies
