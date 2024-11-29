local openssl = require("openssl")
local evp = openssl.cipher.get('aes-128-gcm')
local sha256 = openssl.digest.new("sha256")
local info = evp:info()
local tn = 16 -- tag

-- Hashing and Key Derivation

function hashing(ip)
    local sha256 = openssl.digest.new("sha256")
    local secret = "iOoVXyufFCUqvSqCOkr2Nbu3wWfOuA82"  -- Any secret key, got mine from https://randomkeygen.com/
    local conc = secret .. ip
    sha256:update(conc) -- hashes the secret concatenated with the ip
    local hash = sha256:final()

    -- AES-128-GCM 128-bit key and 96-bit IV
    local key = hash:sub(1, info.key_length)
    local iv = hash:sub(info.key_length + 1, info.key_length + info.iv_length)
    return key, iv
end

-- encryption logic

function aes_encrypt(key, iv, msg)
    local e = evp:encrypt_new()
    assert(e:ctrl(openssl.cipher.EVP_CTRL_GCM_SET_IVLEN, #iv))
    assert(e:init(key, iv))
    e:padding(false)

    local c = assert(e:update(msg))
    c = c .. e:final()
    assert(#c == #msg)

    local tag = assert(e:ctrl(openssl.cipher.EVP_CTRL_GCM_GET_TAG, tn))
    assert(#tag == tn)

    return c, tag
end

function aes_decrypt(key, iv, c, tag)
    local d = evp:decrypt_new()
    assert(d:ctrl(openssl.cipher.EVP_CTRL_GCM_SET_IVLEN, #iv))
    assert(d:init(key, iv))
    d:padding(false)

    local r = assert(d:update(c))
    assert(d:ctrl(openssl.cipher.EVP_CTRL_GCM_SET_TAG, tag))
    r = r .. assert(d:final())
    assert(#r == #c)

    return r
end

-- haproxy logic

-- cookie decrypted on request

core.register_action("decrypt_set_cookie", { "http-req" }, function(txn)
    
    local cookie_headers = txn.http:req_get_headers()["cookie"][0]
    
    local enc_text = openssl.base64(cookie_headers, false)
    local decrypted_cookie = aes_decrypt(key, iv, encrypted_cookie, tag)
    txn.http:req_set_header("Cookie", cookie_name .. "=" .. decrypted_cookie)

end)


-- cookie encrypted on response

core.register_action("encrypt_set_cookie", { "http-res" }, function(txn)

    local set_cookie_headers = txn.http:res_get_headers()["set-cookie"][0]
    local remote_addr = txn.sf:src()

    cookie_name, cookie_value = set_cookie_headers:match("(.+)=(.+)")
    
    key, iv = hashing(remote_addr)
    encrypted_cookie, tag = aes_encrypt(key, iv, cookie_value)
    enc64 = openssl.base64(encrypted_cookie)
    local decrypted_cookie = aes_decrypt(key, iv, encrypted_cookie, tag)

    txn.http:res_set_header("set-cookie", cookie_name .. "=" .. enc64)    

end)

----------------------------------------------------------


-- todo: check for valid cookie header 
-- todo: comments and refactor