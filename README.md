# Hooking Chrome’s SSL functions

The purpose of **NetRipper** is to capture functions that encrypt or decrypt data and send them through the network. This can be easily achieved for applications such as Firefox, where it is enough to find two DLL exported functions: `PR_Read` and `PR_Write`, but it is way more difficult for Google Chrome, where the `SSL_Read` and `SSL_Write` functions are not exported.

The main problem for someone who wants to intercept such calls is that we cannot easily find the functions inside the huge `chrome.dll` file. So we have to manually find them in the binary. But how can we do it?

## Chrome’s source code

In order to achieve our goal, the best starting point might be Chrome’s source code. We can find it [here](https://cs.chromium.org/). It allows us to easily search and navigate through the source code.

We should probably note from the beginning that Google Chrome uses **boringssl**, a fork of OpenSSL. This project is available in the Chromium source code [here](https://boringssl.googlesource.com/).

Now, we have to find the functions we need: `SSL_read` and `SSL_write`, and we can easily find them in the `ssl_lib.cc` file.

### SSL_read

```c
int SSL_read(SSL *ssl, void *buf, int num) {
    int ret = SSL_peek(ssl, buf, num);
    if (ret <= 0) {
        return ret;
    }
    ssl->s3->pending_app_data =
        ssl->s3->pending_app_data.subspan(static_cast<size_t>(ret));
    if (ssl->s3->pending_app_data.empty()) {
        ssl->s3->read_buffer.DiscardConsumed();
    }
    return ret;
}
```
### SSL_write
```c
int SSL_write(SSL *ssl, const void *buf, int num) {
    ssl_reset_error_state(ssl);

    if (ssl->do_handshake == NULL) {
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNINITIALIZED);
        return -1;
    }

    if (ssl->s3->write_shutdown != ssl_shutdown_none) {
        OPENSSL_PUT_ERROR(SSL, SSL_R_PROTOCOL_IS_SHUTDOWN);
        return -1;
    }

    int ret = 0;
    bool needs_handshake = false;
    do {
        if (!ssl_can_write(ssl)) {
            ret = SSL_do_handshake(ssl);
            if (ret < 0) {
                return ret;
            }
            if (ret == 0) {
                OPENSSL_PUT_ERROR(SSL, SSL_R_SSL_HANDSHAKE_FAILURE);
                return -1;
            }
        }

        ret = ssl->method->write_app_data(ssl, &needs_handshake,
                                           (const uint8_t *)buf, num);
    } while (needs_handshake);
    return ret;
}
```

Why are we looking at the code? It is simple: in the binary we might find things that we can also find in the source code, such as strings or specific values.

I actually discovered the base idea that I will present here some time ago, probably here, but I will cover all the aspects in order to make sure anyone will be able to find the functions, not only for Chrome, but also for other tools such as Putty or WinSCP.

### SSL_write function
Even if the SSL_read function does not provide useful information, we can start with SSL_write and we can see something that looks useful:
```c
OPENSSL_PUT_ERROR(SSL, SSL_R_UNINITIALIZED);
```
Here is the OPENSSL_PUT_ERROR macro:
```c
#define OPENSSL_PUT_ERROR(library, reason) \
    ERR_put_error(ERR_LIB_##library, 0, reason, __FILE__, __LINE__)
```


Some things are very useful:
- `ERR_put_error` is a function call
- `reason` is the second parameter, and in our case `SSL_R_UNINITIALIZED` has the value 226 (0xE2)
- `__FILE__` is the actual filename, full path of `ssl_lib.cc`
- `__LINE__` is the current line number in `ssl_lib.cc` file

All this information can help us to find the `SSL_write` function. Why? We know it is a function call, so the parameters (such as `reason`, `__FILE__` and `__LINE__`) will be placed on the stack (x86). We know the reason (0xE2), the `__FILE__` (`ssl_lib.cc`), and the `__LINE__` (1060 or 0x424 in this version).

But what if there are different versions used? The line numbers can be totally different. Well, in this case, we have to take a look at how Google Chrome uses BoringSSL.

We can find the specific version of Chrome [here](https://chromium.googlesource.com/chromium/src/). For example, right now on x86 I have this version: **Version 65.0.3325.181 (Official Build) (32-bit)**. We can find its source code [here](https://chromium.googlesource.com/chromium/src/).

Now, we have to find the BoringSSL code, but it looks like it is not there. However, we can find the `DEPS` file very useful and extract some information:
```c
vars = {
...
'boringssl_git': 'https://boringssl.googlesource.com',
'boringssl_revision': '94cd196a80252c98e329e979870f2a462cc4f402',
}
```
We can see that our Chrome version uses `https://boringssl.googlesource.com` to get BoringSSL and it uses this revision: `94cd196a80252c98e329e979870f2a462cc4f402`. Based on this, we can get the exact code for BoringSSL right [here](https://boringssl.googlesource.com/). 

### Steps to Find the SSL_write Function Address

1. Search for `ssl_lib.cc` filename in the read-only section of `chrome.dll` (.rdata)
2. Get the full path and search for references
3. Check all references to the string and find the right one based on `reason` and line number parameters

### SSL_read Function

It was not difficult to find the `SSL_write` function because there is an `OPENSSL_PUT_ERROR`, but we do not have it on `SSL_read`. Let’s see how `SSL_read` works and follow it.

We can easily see that it calls `SSL_peek`:
```c
int ret = SSL_peek(ssl, buf, num);
```
We can see that `SSL_peek` will call `ssl_read_impl` function:
```c
int SSL_peek(SSL *ssl, void *buf, int num) {
    int ret = ssl_read_impl(ssl);
    if (ret <= 0) {
        return ret;
    }
...
}
```

And `ssl_read_impl` function is trying to help us:
```c
static int ssl_read_impl(SSL *ssl) {
    ssl_reset_error_state(ssl);
    if (ssl->do_handshake == NULL) {
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNINITIALIZED);
        return -1;
    }
}
...
```
We can search in the code and find out that `ssl_read_impl` function is called just two times, by `SSL_peek` and `SSL_shutdown` functions, so it should be pretty easy to find `SSL_peek`. After we find `SSL_peek`, `SSL_read` is straightforward to find.

### Chrome on 32 bits

Since we have the general idea about how we can find the functions, let’s find them. I will use `x64dbg`, but you can probably use any other debugger. We have to go to the “Memory” tab and find `chrome.dll`. We will need to do two things first:

1. Open the code section in the disassembler, so right click on “.text” and choose “Follow in Disassembler”
2. Open the read-only data section in the dump window, so right click on “.rdata” and choose “Follow in Dump”

We have to find now the `ssl_lib.cc` string in the dump window, so right click inside the window, choose “Find Pattern” and search for our ASCII string. You should have a single result, double click it and go back until you find the full path of the `ssl_lib.cc` file. Right click the first byte of the full path and choose “Find References” to see where we can find it used (OPENSSL_PUT_ERROR function calls).

It looks like we have multiple references, but we can take them one by one and find the right one. Here is the result. 

Let’s go to the last one for example, to see how it looks like.
```c
6D44325C | 68 AD 03 00 00 | push 3AD |
6D443261 | 68 24 24 E9 6D | push chrome.6DE92424 | 6DE92424:"../../third_party/boringssl/src/ssl/ssl_lib.cc"
6D443266 | 6A 44 | push 44 |
6D443268 | 6A 00 | push 0 |
6D44326A | 6A 10 | push 10 |
6D44326C | E8 27 A7 00 FF | call chrome.6C44D998 |
6D443271 | 83 C4 14 | add esp,14 |
```

It looks exactly as we expected, a function call with five parameters. As you probably know, the parameters are pushed on the stack from right to left and we have the following:
- `push 3AD` – The line number
- `push chrome.6DE92424` – Our string, the file path
- `push 44` – The reason
- `push 0` – The parameter which is always 0
- `push 10` – First parameter
- `call chrome.6C44D998` – Call the `ERR_put_error` function
- `add esp,14` – Clean the stack

However, `0x3AD` represents line number 941, which is inside `ssl_do_post_handshake`, so it is not what we need.

### SSL_write

`SSL_write` has calls to this function on line numbers 1056 (0x420) and 1061 (0x425) so we will need to find the call to the function with a `push 420` or `push 425` at the beginning. Going through the results will take just a few seconds until we find it:
```c
6BBA52D0 | 68 25 04 00 00 | push 425 |
6BBA52D5 | 68 24 24 E9 6D | push chrome.6DE92424 | 6DE92424:"../../third_party/boringssl/src/ssl/ssl_lib.cc"
6BBA52DA | 68 C2 00 00 00 | push C2 |
6BBA52DF | EB 0F | jmp chrome.6BBA52F0 |
6BBA52E1 | 68 20 04 00 00 | push 420 |
6BBA52E6 | 68 24 24 E9 6D | push chrome.6DE92424 | 6DE92424:"../../third_party/boringssl/src/ssl/ssl_lib.cc"
6BBA52EB | 68 E2 00 00 00 | push E2 |
6BBA52F0 | 6A 00 | push 0 |
6BBA52F2 | 6A 10 | push 10 |
6BBA52F4 | E8 9F 86 8A 00 | call chrome.6C44D998 |
```
We can see here both function calls, but with just a small mention that the first one is optimized. Now, we have just to go back until we find something that looks like the start of a function. While this might not be always the case for other functions, it should work in our case and we can easily find it by classic function prologue:
```c
6BBA5291 | 55 | push ebp |
6BBA5292 | 89 E5 | mov ebp,esp |
6BBA5294 | 53 | push ebx |
6BBA5295 | 57 | push edi |
6BBA5296 | 56 | push esi |
```
Let’s place a breakpoint at `6BBA5291` and see what happens when we use Chrome to browse some HTTPS website (to avoid issues, browse a website without SPDY or HTTP/2.0).

Here is an example of what we can get on the top of the stack when the breakpoint is triggered:
```c
06DEF274 6A0651E8 return to chrome.6A0651E8 from chrome.6A065291
06DEF278 0D48C9C0 ; First parameter of SSL_write (pointer to SSL)
06DEF27C 0B3C61F8 ; Second parameter, the payload
06DEF280 0000051C ; Third parameter, payload size
```
If you right click the second parameter and select “Follow DWORD in Dump”, you should see the plain-text data, such as:
```c
0B3C61F8 50 4F 53 54 20 2F 61 68 2F 61 6A 61 78 2F 72 65 POST /ah/ajax/re
0B3C6208 63 6F 72 64 2D 69 6D 70 72 65 73 73 69 6F 6E 73 cord-impressions
0B3C6218 3F 63 34 69 3D 65 50 6D 5F 66 48 70 72 78 64 48 ?c4i=ePm_fHprxdH
```
### SSL_read

Let’s find now the `SSL_read` function. We should find the call to `OPENSSL_PUT_ERROR` from the `ssl_read_impl` function. This call is available in line 962 (0x3C2). Let’s go again through the results and find it. Here it is:
```c
6B902FAC | 68 C2 03 00 00 | push 3C2 |
6B902FB1 | 68 24 24 35 6C | push chrome.6C352424 | 6C352424:"../../third_party/boringssl/src/ssl/ssl_lib.cc"
6B902FB6 | 68 E2 00 00 00 | push E2 |
6B902FBB | 6A 00 | push 0 |
6B902FBD | 6A 10 | push 10 |
6B902FBF | E8 D4 A9 00 FF | call chrome.6A90D998 |
```
Now, we should find the beginning of the function, which should be easy. Right click the first instruction (`push EBP`), go to “Find references to” and “Selected Address(es)”. We should find only one call to the function, which should be `SSL_peek`. Find the first instruction of `SSL_peek` and repeat the same step. We should have only one result, which is the call to `SSL_peek` from `SSL_read`. So we got it.
```c
6A065F52 | 55 | push ebp | ; SSL_read function
6A065F53 | 89 E5 | mov ebp,esp |
...
6A065F60 | 57 | push edi |
6A065F61 | E8 35 00 00 00 | call chrome.6A065F9B | ; Call SSL_peek
```
Let’s place a breakpoint, and we can see the following on a normal call:
```c
06DEF338 6A065D8F return to chrome.6A065D8F from chrome.6A065F52
06DEF33C 0AF39EA0 ; First parameter of SSL_read, pointer to SSL
06DEF340 0D4D5880 ; Second parameter, the payload
06DEF344 00001000 ; Third parameter, payload length
```
Now, we should right click the second parameter and choose “Follow DWORD in Dump” before pressing the “Execute til return” button, in order to stop in the debugger at the end of the function, so after the data was read in the buffer. We should be able to see the plain-text data in the Dump window, where we selected the payload.
```c
0D4D5880 48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D HTTP/1.1 200 OK.
0D4D5890 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 69 .Content-Type: i
0D4D58A0 6D 61 67 65 2F 67 69 66 0D 0A 54 72 61 6E 73 66 mage/gif..Transf
```
We managed to find it as well.

## Conclusion

It might look difficult at the beginning, but as you can see, it is pretty easy if we follow the source code in the binary. This approach should work for most of the open-source applications.

As the x64 version would be very similar and the only difference would be the assembly code, it will not be detailed here.

However, please note that hooking those functions might result in unstable behavior and possible crashes.