

library(openssl)

# Reference: 
# wiki https://en.wikipedia.org/wiki/PBKDF2
# python hashlib https://github.com/python/cpython/blob/3.10/Lib/hashlib.py
# result can be check here https://asecuritysite.com/hash/pb2

pbkdf2_hmac <- function(hash_name, password, salt, iterations, dklen=NULL){
    # copy from python hashlib.pbkdf2_hmac
    trans_36_hex = "36373435323330313e3f3c3d3a3b383926272425222320212e2f2c2d2a2b282916171415121310111e1f1c1d1a1b181906070405020300010e0f0c0d0a0b080976777475727370717e7f7c7d7a7b787966676465626360616e6f6c6d6a6b686956575455525350515e5f5c5d5a5b585946474445424340414e4f4c4d4a4b4849b6b7b4b5b2b3b0b1bebfbcbdbabbb8b9a6a7a4a5a2a3a0a1aeafacadaaaba8a996979495929390919e9f9c9d9a9b989986878485828380818e8f8c8d8a8b8889f6f7f4f5f2f3f0f1fefffcfdfafbf8f9e6e7e4e5e2e3e0e1eeefecedeaebe8e9d6d7d4d5d2d3d0d1dedfdcdddadbd8d9c6c7c4c5c2c3c0c1cecfcccdcacbc8c9"
    
    trans_5C_hex = "5c5d5e5f58595a5b54555657505152534c4d4e4f48494a4b44454647404142437c7d7e7f78797a7b74757677707172736c6d6e6f68696a6b64656667606162631c1d1e1f18191a1b14151617101112130c0d0e0f08090a0b04050607000102033c3d3e3f38393a3b34353637303132332c2d2e2f28292a2b2425262720212223dcdddedfd8d9dadbd4d5d6d7d0d1d2d3cccdcecfc8c9cacbc4c5c6c7c0c1c2c3fcfdfefff8f9fafbf4f5f6f7f0f1f2f3ecedeeefe8e9eaebe4e5e6e7e0e1e2e39c9d9e9f98999a9b94959697909192938c8d8e8f88898a8b8485868780818283bcbdbebfb8b9babbb4b5b6b7b0b1b2b3acadaeafa8a9aaaba4a5a6a7a0a1a2a3"
    
    trans_base_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    
    
    diy_translate <- function(x, from, to){
        y <- raw(length = length(x))
        for (i in 1:length(x)){
            y[i] <- to[which(from == x[i])]
        }
        return(y)
    }
    
    blocksize <- 64
    if (hash_name == "crc32") 
        blocksize <- 4
    if (hash_name == "sha512") 
        blocksize <- 128
    
    
    if(iterations < 1 ){
        print("iterations must >= 1")
        return(NULL)
    }
    if(is.null(dklen)){
        dklen = 32
    }
    if(dklen < 1 ){
        print("dklen must >= 1")
        return(NULL)
    }
    
    if (nchar(rawToChar(password)) > blocksize){
        password = sha256(password)
    }else{
        h1 = as.hexmode(c(password, rep(0, 64 - nchar(rawToChar(password)))))
        password = wkb::hex2raw(paste(h1, collapse = ''))
    }
    
    
    dkey = raw()
    # loop = 1
    
    init_sha256  = sha256(raw())
    
    inner_part = diy_translate(password, from = wkb::hex2raw(trans_base_hex), to = wkb::hex2raw(trans_36_hex))
    outer_part = diy_translate(password, from = wkb::hex2raw(trans_base_hex), to = wkb::hex2raw(trans_5C_hex))
    # inner_sha256 = sha256(diy_translate(password, from = wkb::hex2raw(trans_base_hex), to = wkb::hex2raw(trans_36_hex)))
    # outer_sha256 = sha256(diy_translate(password, from = wkb::hex2raw(trans_base_hex), to = wkb::hex2raw(trans_5C_hex)))
    # 
    loop = 1
    while(length(dkey) < dklen){
        
        salt_1 = c(salt, wkb::hex2raw(stringr::str_pad(loop, 8, 'left', '0') ))
        rkey = wkb::hex2raw('00')
        inner_update = c(
            inner_part, 
            salt_1)
        outer_update = c(outer_part, sha256(inner_update))
        outer_update_sha256 = sha256(outer_update)
        rkey = outer_update_sha256
        
        
        if (iterations == 1){
            dkey = c(dkey, rkey)
        }else{
            for (i in 1:(iterations - 1)){
    
                inner_update = c(inner_part, outer_update_sha256)
                outer_update = c(outer_part, sha256(inner_update))
                outer_update_sha256 = sha256(outer_update)
                rkey= xor(outer_update_sha256, rkey)
                
            }
        }
        loop = loop + 1
        dkey = c(dkey, rkey)
    }
    return(dkey[1:dklen])
}


key_password = charToRaw('D23ABC@#56')
iv_password = charToRaw('apidata/api/gk/score/special')
salt = charToRaw('secret')


print(pbkdf2_hmac('sha256', iv_password, charToRaw('secret'), 3, 16))
print(pbkdf2_hmac('sha256', key_password, charToRaw('secret'), 3))
