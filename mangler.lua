local openssl = require("openssl")
local evp = openssl.cipher.get('aes-128-gcm')
local sha256 = openssl.digest.new("sha256")
local info = evp:info()
local tn = 16 -- tag

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
e = evp:encrypt_new()

function aes_encrypt(key, iv, msg, e, tn)
    assert(e:ctrl(openssl.cipher.EVP_CTRL_GCM_SET_IVLEN, #iv))
    assert(e:init(key, iv))
    e:padding(false)

    local c = assert(e:update(msg))
    c = c .. e:final()
    assert(#c==#msg)

    local tag = assert(e:ctrl(openssl.cipher.EVP_CTRL_GCM_GET_TAG, tn))
   assert(#tag==tn)

    return c, tag
end




-- haproxy logic

-- cookie decrypted on request

core.register_action("decrypt_set_cookie", { "http-req" }, function(txn)
    local set_cookie_headers = txn.http:req_get_headers()["cookie"][0]
    local upper_cookie_headers = string.upper(set_cookie_headers)
    --test block
    

    -- txn.http:req_set_header("Cookie", key)

    -- txn.http:req_set_header("Cookie", upper_cookie_headers)

end)


-- cookie encrypted on response

core.register_action("encrypt_set_cookie", { "http-res" }, function(txn)
    local set_cookie_headers = txn.http:res_get_headers()["set-cookie"][0]
    -- local lower_cookie_headers = string.lower(set_cookie_headers)
    local remote_addr = txn.sf:src()
    local key, iv = hashing(remote_addr)
    local encrypted_cookie, tag = aes_encrypt(key, iv, set_cookie_headers, e, tn)
    local enc64 = openssl.base64(encrypted_cookie)

    -- test block
    -- local test = openssl.version()
    txn.http:res_set_header("set-cookie", enc64)    

    -- txn.http:res_set_header("set-cookie", lower_cookie_headers)
end)


-- todo: encrypt cookies
-- todo: check for valid cookie header
-- todo: 
-- todo: comments and refactor