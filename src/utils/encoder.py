"""
what this module is supposed to do:
URL encode (encode+decode)
Double URL encode
Base64 encoding
HTML entity encoding
Hex encoding

for url encoding:
    i will import urllib.parse
    define a function urlencode():
        make the function return urllib.parse.quote(the string)
    define a function urldecode():
        make the function return urllib.parse.unquote(the string)
    print the encoded/decoded statement
    will have to run an if/else loop depending on whether decoder is called or encoder
    might run a nested function, i will see

for double url encoding:
    will import urllib.parse()
    give it a string
    make it do a first_encode
    then will make it a second_encode
    print the second_encode variable
    do I have to make a double url decoding? I dont know

for Base64 Encoding/decoding:
    I will import base64
    define a function b64():
        convert input string to string.encode("utf-8"), this converts it to utf-8
        encoded_bytes=base64.b64encode("utf-8 encoded bytes"). this encodes the bytes to base64
        encoded_string=encoded_bytes.decode("utf-8"). this turns the base64 bytes to string

        for decoding:
        it will take encoded_data
        convert it into decoded_bytes using base64.b64decode(encoded_data)
        convert that into decoded_string using decoded_bytes.decode("utf-8")
    Then print encoded/decoded string
    I will most probably turn this into a nested function with a case switch condition in the end

For HTML entity encoding:
            


"""