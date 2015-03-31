//
//  http_constants.cc
//

#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <atomic>
#include <mutex>

#include "http_constants.h"


/*
 * HTTP status codes
 */

const char* kHTTPStatusTextNone =                           "No Status";
const char* kHTTPStatusTextContinue =                       "Continue";
const char* kHTTPStatusTextSwitchingProtocols =             "Switching Protocols";
const char* kHTTPStatusTextOK =                             "OK";
const char* kHTTPStatusTextCreated =                        "Created";
const char* kHTTPStatusTextAccepted =                       "Accepted";
const char* kHTTPStatusTextNonAuthoritativeInformation =    "Non-Authoritative Information";
const char* kHTTPStatusTextNoContent =                      "No Content";
const char* kHTTPStatusTextResetContent =                   "Reset Content";
const char* kHTTPStatusTextPartialContent =                 "Partial Content";
const char* kHTTPStatusTextMultiStatusResponse =            "Multi Status Response";
const char* kHTTPStatusTextMultipleChoices =                "Multiple Choices";
const char* kHTTPStatusTextMovedPermanently =               "Moved Permanently";
const char* kHTTPStatusTextFound =                          "Found";
const char* kHTTPStatusTextSeeOther =                       "See Other";
const char* kHTTPStatusTextNotModified =                    "Not Modified";
const char* kHTTPStatusTextUseProxy =                       "Use Proxy";
const char* kHTTPStatusTextTemporaryRedirect =              "Temporary Redirect";
const char* kHTTPStatusTextBadRequest =                     "Bad Request";
const char* kHTTPStatusTextUnauthorized =                   "Unauthorized";
const char* kHTTPStatusTextPaymentRequired =                "Payment Required";
const char* kHTTPStatusTextForbidden =                      "Forbidden";
const char* kHTTPStatusTextNotFound =                       "Not Found";
const char* kHTTPStatusTextMethodNotAllowed =               "Method Not Allowed";
const char* kHTTPStatusTextNotAcceptable =                  "Not Acceptable";
const char* kHTTPStatusTextProxyAuthenticationRequired =    "Proxy Authentication Required";
const char* kHTTPStatusTextRequestTimeout =                 "Request Time-out";
const char* kHTTPStatusTextConflict =                       "Conflict";
const char* kHTTPStatusTextGone =                           "Gone";
const char* kHTTPStatusTextLengthRequired =                 "Length Required";
const char* kHTTPStatusTextPreconditionFailed =             "PreconditionFailed";
const char* kHTTPStatusTextRequestEntityTooLarge =          "Request Entity Too Large";
const char* kHTTPStatusTextRequestURITooLarge =             "Request-URI Too Large";
const char* kHTTPStatusTextUnsupportedMediaType =           "Unsupported Media Type";
const char* kHTTPStatusTextRequestedRangeNotSatisfiable =   "Requested range not satisfiable";
const char* kHTTPStatusTextExpectationFailed =              "Expectation Failed";
const char* kHTTPStatusTextUnprocessableEntity =            "Unprocessable Entity";
const char* kHTTPStatusTextLocked =                         "Locked";
const char* kHTTPStatusTextFailedDependency =               "Failed Dependency";
const char* kHTTPStatusTextInternalServerError =            "Internal Server Error";
const char* kHTTPStatusTextNotImplemented =                 "Not Implemented";
const char* kHTTPStatusTextBadGateway =                     "Bad Gateway";
const char* kHTTPStatusTextServiceUnavailable =             "Service Unavailable";
const char* kHTTPStatusTextGatewayTimeout =                 "Gateway Time-out";
const char* kHTTPStatusTextHTTPVersionNotSupported =        "HTTP Version not supported";
const char* kHTTPStatusTextInsufficientStorage =            "Insufficient Storage";

HTTPStatusEntry kHTTPStatusTable[] =
{
    { HTTPStatusCodeNone,                              kHTTPStatusTextNone },
    { HTTPStatusCodeContinue,                          kHTTPStatusTextContinue },
    { HTTPStatusCodeSwitchingProtocols,                kHTTPStatusTextSwitchingProtocols },
    { HTTPStatusCodeOK,                                kHTTPStatusTextOK },
    { HTTPStatusCodeCreated,                           kHTTPStatusTextCreated },
    { HTTPStatusCodeAccepted,                          kHTTPStatusTextAccepted },
    { HTTPStatusCodeNonAuthoritativeInformation,       kHTTPStatusTextNonAuthoritativeInformation },
    { HTTPStatusCodeNoContent,                         kHTTPStatusTextNoContent },
    { HTTPStatusCodeResetContent,                      kHTTPStatusTextResetContent },
    { HTTPStatusCodePartialContent,                    kHTTPStatusTextPartialContent },
    { HTTPStatusCodeMultiStatusResponse,               kHTTPStatusTextMultiStatusResponse },
    { HTTPStatusCodeMultipleChoices,                   kHTTPStatusTextMultipleChoices },
    { HTTPStatusCodeMovedPermanently,                  kHTTPStatusTextMovedPermanently },
    { HTTPStatusCodeFound,                             kHTTPStatusTextFound },
    { HTTPStatusCodeSeeOther,                          kHTTPStatusTextSeeOther },
    { HTTPStatusCodeNotModified,                       kHTTPStatusTextNotModified },
    { HTTPStatusCodeUseProxy,                          kHTTPStatusTextUseProxy },
    { HTTPStatusCodeTemporaryRedirect,                 kHTTPStatusTextTemporaryRedirect },
    { HTTPStatusCodeBadRequest,                        kHTTPStatusTextBadRequest },
    { HTTPStatusCodeUnauthorized,                      kHTTPStatusTextUnauthorized },
    { HTTPStatusCodePaymentRequired,                   kHTTPStatusTextPaymentRequired },
    { HTTPStatusCodeForbidden,                         kHTTPStatusTextForbidden },
    { HTTPStatusCodeNotFound,                          kHTTPStatusTextNotFound },
    { HTTPStatusCodeMethodNotAllowed,                  kHTTPStatusTextMethodNotAllowed },
    { HTTPStatusCodeNotAcceptable,                     kHTTPStatusTextNotAcceptable },
    { HTTPStatusCodeProxyAuthenticationRequired,       kHTTPStatusTextProxyAuthenticationRequired },
    { HTTPStatusCodeRequestTimeout,                    kHTTPStatusTextRequestTimeout },
    { HTTPStatusCodeConflict,                          kHTTPStatusTextConflict },
    { HTTPStatusCodeGone,                              kHTTPStatusTextGone },
    { HTTPStatusCodeLengthRequired,                    kHTTPStatusTextLengthRequired },
    { HTTPStatusCodePreconditionFailed,                kHTTPStatusTextPreconditionFailed },
    { HTTPStatusCodeRequestEntityTooLarge,             kHTTPStatusTextRequestEntityTooLarge },
    { HTTPStatusCodeRequestURITooLarge,                kHTTPStatusTextRequestURITooLarge },
    { HTTPStatusCodeUnsupportedMediaType,              kHTTPStatusTextUnsupportedMediaType },
    { HTTPStatusCodeRequestedRangeNotSatisfiable,      kHTTPStatusTextRequestedRangeNotSatisfiable },
    { HTTPStatusCodeExpectationFailed,                 kHTTPStatusTextExpectationFailed },
    { HTTPStatusCodeUnprocessableEntity,               kHTTPStatusTextUnprocessableEntity },
    { HTTPStatusCodeLocked,                            kHTTPStatusTextLocked },
    { HTTPStatusCodeFailedDependency,                  kHTTPStatusTextFailedDependency },
    { HTTPStatusCodeInternalServerError,               kHTTPStatusTextInternalServerError },
    { HTTPStatusCodeNotImplemented,                    kHTTPStatusTextNotImplemented },
    { HTTPStatusCodeBadGateway,                        kHTTPStatusTextBadGateway },
    { HTTPStatusCodeServiceUnavailable,                kHTTPStatusTextServiceUnavailable },
    { HTTPStatusCodeGatewayTimeout,                    kHTTPStatusTextGatewayTimeout },
    { HTTPStatusCodeHTTPVersionNotSupported,           kHTTPStatusTextHTTPVersionNotSupported },
    { HTTPStatusCodeInsufficientStorage,               kHTTPStatusTextInsufficientStorage },
    { HTTPStatusCodeLast,                              nullptr },
};


/*
 * HTTP versions
 */

const char* kHTTPVersionNone =              "";
const char* kHTTPVersion10 =                "HTTP/1.0";
const char* kHTTPVersion11 =                "HTTP/1.1";
const char* kHTTPVersion20 =                "HTTP/2.0";

HTTPVersionEntry kHTTPVersionTable[] =
{
    { HTTPVersionNone,      kHTTPVersionNone },
    { HTTPVersion10,        kHTTPVersion10 },
    { HTTPVersion11,        kHTTPVersion11 },
    { HTTPVersion20,        kHTTPVersion20 },
    { HTTPVersionLast,      nullptr },
};


/*
 * HTTP request methods
 */

// RFC2616
const char* kHTTPMethodNone =               "";
const char* kHTTPMethodGET =                "GET";
const char* kHTTPMethodHEAD =               "HEAD";
const char* kHTTPMethodPOST =               "POST";
const char* kHTTPMethodPUT =                "PUT";
const char* kHTTPMethodDELETE =             "DELETE";
const char* kHTTPMethodOPTIONS =            "OPTIONS";
const char* kHTTPMethodTRACE =              "TRACE";
const char* kHTTPMethodCONNECT =            "CONNECT";

// RFC4918 - HTTP Extensions for Web Distributed Authoring and Versioning (WebDAV)
const char* kHTTPMethodPROPFIND =           "PROPFIND";
const char* kHTTPMethodPROPPATCH =          "PROPPATCH";
const char* kHTTPMethodMKCOL =              "MKCOL";
const char* kHTTPMethodCOPY =               "COPY";
const char* kHTTPMethodMOVE =               "MOVE";
const char* kHTTPMethodLOCK =               "LOCK";
const char* kHTTPMethodUNLOCK =             "UNLOCK";

// Subversion - http://svn.apache.org/repos/asf/subversion/trunk/notes/http-and-webdav/webdav-protocol
const char* kHTTPMethodMKACTIVITY =         "MKACTIVITY";
const char* kHTTPMethodREPORT =             "REPORT";
const char* kHTTPMethodCHECKOUT =           "CHECKOUT";
const char* kHTTPMethodMERGE =              "MERGE";

// See RFC7237 - Initial Hypertext Transfer Protocol (HTTP) Method Registrations
// See IANA HTTP Method Registry - http://www.iana.org/assignments/http-methods/http-methods.xhtml


HTTPMethodEntry kHTTPMethodTable[] =
{
    { HTTPMethodNone,       kHTTPMethodNone },
    { HTTPMethodGET,        kHTTPMethodGET },
    { HTTPMethodHEAD,       kHTTPMethodHEAD },
    { HTTPMethodPOST,       kHTTPMethodPOST },
    { HTTPMethodPUT,        kHTTPMethodPUT },
    { HTTPMethodDELETE,     kHTTPMethodDELETE },
    { HTTPMethodOPTIONS,    kHTTPMethodOPTIONS },
    { HTTPMethodTRACE,      kHTTPMethodTRACE },
    { HTTPMethodCONNECT,    kHTTPMethodCONNECT },
    { HTTPMethodPROPFIND,   kHTTPMethodPROPFIND },
    { HTTPMethodPROPPATCH,  kHTTPMethodPROPPATCH },
    { HTTPMethodMKCOL,      kHTTPMethodMKCOL },
    { HTTPMethodCOPY,       kHTTPMethodCOPY },
    { HTTPMethodMOVE,       kHTTPMethodMOVE },
    { HTTPMethodLOCK,       kHTTPMethodLOCK },
    { HTTPMethodUNLOCK,     kHTTPMethodUNLOCK },
    { HTTPMethodMKACTIVITY, kHTTPMethodMKACTIVITY },
    { HTTPMethodREPORT,     kHTTPMethodREPORT },
    { HTTPMethodCHECKOUT,   kHTTPMethodCHECKOUT },
    { HTTPMethodMERGE,      kHTTPMethodMERGE },
    { HTTPMethodLast,       nullptr },
};


/*
 * HTTP request headers
 */

// HTTP2.0 header compression see https://tools.ietf.org/html/draft-ietf-httpbis-header-compression-10

const char* kHTTPHeaderHost =               "Host";                 // Host: www.example.com
const char* kHTTPHeaderUserAgent =          "User-Agent";           // User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0
const char* kHTTPHeaderAccept =             "Accept";               // Accept: image/png,image/*;q=0.8,*/*;q=0.5
const char* kHTTPHeaderAcceptLanguage =     "Accept-Language";      // Accept-Language: en-US,en;q=0.5
const char* kHTTPHeaderAcceptEncoding =     "Accept-Encoding";      // Accept-Encoding: gzip, deflate
const char* kHTTPHeaderAcceptCharset =      "Accept-Charset";       // Accept-Charset: utf-8, iso8859-1;q=0.8
const char* kHTTPHeaderAuthorization =      "Authorization";        // Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQK            (username:password in Base64)
const char* kHTTPHeaderCookie =             "Cookie";               // Cookie: name=value; name2=value2
const char* kHTTPHeaderExpect =             "Expect";               // Expect: 100-continue     (if sending body, server replies "HTTP/1.1 100 Continue" CRLF CRLF)
const char* kHTTPHeaderFrom =               "From";                 // From: user@example.com
const char* kHTTPHeaderIfMatch =            "If-Match";             // If-Match: "ZXRhZ2V0YWcK"
const char* kHTTPHeaderIfModifiedSince =    "If-Modified-Since";    // If-Modified-Since: Mon, 02 Apr 2012 02:13:37 GMT
const char* kHTTPHeaderIfNoneMatch =        "If-None-Match";        // If-None-Match: W/"ZXRhZ2V0YWcK"
const char* kHTTPHeaderIfRange =            "If-Range";             // If-Range: "ZXRhZ2V0YWcK"
const char* kHTTPHeaderIfUnmodifiedSince =  "If-Unmodified-Since";  // If-Modified-Since: Mon, 02 Apr 2012 02:13:37 GMT
const char* kHTTPHeaderMaxForwards =        "Max-Forwards";         // Max-Forwards: 9
const char* kHTTPHeaderProxyAuthorization=  "Proxy-Authorization";  // Proxy-Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQK
const char* kHTTPHeaderRange =              "Range";                // Range: bytes=2048-4095,4096-6143,6144-8191,8192-10239
const char* kHTTPHeaderReferer =            "Referer";              // Referer: https://www.google.com.sg/
const char* kHTTPHeaderTE =                 "TE";                   // TE: trailers, deflate;q=0.5
const char* kHTTPHeaderDepth =              "Depth";                // Depth: 0                                                 (RFC4918 recursion)
const char* kHTTPHeaderDestination =        "Destination";          // Destination: /foo/bar                                    (RFC4918 destination of COPY or MOVE)
const char* kHTTPHeaderIf =                 "If";                   // If: (<locktoken:a-write-lock-token> ["I am an ETag"])    (RFC4918 extended if)
const char* kHTTPHeaderLockToken =          "Lock-Token";           // Lock-Token: <opaquelocktoken:a515cfa4-5da4>              (RFC4918 lock token)
const char* kHTTPHeaderOverwrite =          "Overwrite";            // Overwrite: "T"                                           (RFC4918 overwrite)
const char* kHTTPHeaderTimeout =            "Timeout";              // Timeout: Infinite, Second-4100000000                     (RFC4918 lock timeout)


/* response headers */

const char* kHTTPHeaderServer =             "Server";               // Server: objstore/0.0
const char* kHTTPHeaderSetCookie =          "SetCookie";            // Set-Cookie: name2=value2; Expires=Wed, 09 Jun 2021 10:18:14 GMT
const char* kHTTPHeaderAcceptRanges =       "Accept-Ranges";        // Accept-Ranges: bytes
const char* kHTTPHeaderWWWAuthenticate =    "WWW-Authenticate";     // Basic realm="myRealm"                  (included in 401 Unauthorized response messages)
const char* kHTTPHeaderAge =                "Age";                  // Age: 60                                (age in seconds sent by caches)
const char* kHTTPHeaderETAG =               "ETag";                 // ETag: "ZXRhZ2V0YWcK"
const char* kHTTPHeaderLocation =           "Location";             // Location: http://www.example.com/redirected/
const char* kHTTPHeaderProxyAuthenticate =  "Proxy-Authenticate";   // Proxy-Authenticate: Basic realm="myRealm"
const char* kHTTPHeaderRetryAfter =         "Retry-After";          // Retry-After: 120                       (can be sent with 503 (Service Unavailable))
const char* kHTTPHeaderTrailers =           "Trailers";             // Trailers: Content-MD5                  (chunked encoding trailing headers)


/* general headers */

const char* kHTTPHeaderConnection =         "Connection";           // Connection: keep-alive
const char* kHTTPHeaderCacheControl =       "Cache-Control";        // Cache-Control: max-age=0
const char* kHTTPHeaderDate =               "Date";                 // Date: Sat, 09 Nov 2013 11:25:06 GMT
const char* kHTTPHeaderTransferEncoding =   "Transfer-Encoding";    // Transfer-Encoding: chunked
const char* kHTTPHeaderUpgrade =            "Upgrade";              // Upgrade: HTTP/2.0
const char* kHTTPHeaderVary =               "Vary";                 // Vary: Accept
const char* kHTTPHeaderVia =                "Via";                  // Via: 1.0 ricky
const char* kHTTPHeaderWarning =            "Warning";              // Warning: 37 "P1" "My hovercraft is full of eels"
const char* kHTTPHeaderDAV =                "DAV";                  // DAV: 1                                 (RFC4918 compliance: "1" | "2" | "3" | extend)


/* entity header fields */

const char* kHTTPHeaderAllow =              "Allow";                // Allow: GET, HEAD, PUT
const char* kHTTPHeaderContentEncoding =    "Content-Encoding";     // Content-Encoding: gzip
const char* kHTTPHeaderContentLanguage =    "Content-Language";     // Content-Language: en
const char* kHTTPHeaderContentLength =      "Content-Length";       // Content-Length: 8986
const char* kHTTPHeaderContentLocation =    "Content-Location";     // Content-location: /index.en.html
const char* kHTTPHeaderContentMD5 =         "Content-MD5";          // Content-MD5: OQroDtMY0ttn/mMQJEZrjA==  (base64 of binary MD5)
const char* kHTTPHeaderContentRange =       "Content-Range";        // Content-Range: bytes 0-499/1234        first 500 bytes of 1234 byte object)
const char* kHTTPHeaderContentType =        "Content-Type";         // Content: text/html
const char* kHTTPHeaderExpires =            "Expires";              // Expires: Thu, 01 Dec 1994 16:00:00 GMT
const char* kHTTPHeaderLastModified =       "Last-Modified";        // Last-Modified: Fri, 12 Apr 2013 00:31:11 GMT
const char* kHTTPHeaderPragma =             "Pragma";               // Pragma: no-cache                       (note this is equivalent to Cache-Control: no-cache)


HTTPHeaderEntry kHTTPHeaderTable[] =
{
    { kHTTPHeaderHost,                  HTTPHeaderTypeRequest },
    { kHTTPHeaderUserAgent,             HTTPHeaderTypeRequest },
    { kHTTPHeaderAccept,                HTTPHeaderTypeRequest },
    { kHTTPHeaderAcceptLanguage,        HTTPHeaderTypeRequest },
    { kHTTPHeaderAcceptEncoding,        HTTPHeaderTypeRequest },
    { kHTTPHeaderAcceptCharset,         HTTPHeaderTypeRequest },
    { kHTTPHeaderAuthorization,         HTTPHeaderTypeRequest },
    { kHTTPHeaderCookie,                HTTPHeaderTypeRequest },
    { kHTTPHeaderExpect,                HTTPHeaderTypeRequest },
    { kHTTPHeaderFrom,                  HTTPHeaderTypeRequest },
    { kHTTPHeaderIfMatch,               HTTPHeaderTypeRequest },
    { kHTTPHeaderIfModifiedSince,       HTTPHeaderTypeRequest },
    { kHTTPHeaderIfNoneMatch,           HTTPHeaderTypeRequest },
    { kHTTPHeaderIfRange,               HTTPHeaderTypeRequest },
    { kHTTPHeaderIfUnmodifiedSince,     HTTPHeaderTypeRequest },
    { kHTTPHeaderMaxForwards,           HTTPHeaderTypeRequest },
    { kHTTPHeaderProxyAuthorization,    HTTPHeaderTypeRequest },
    { kHTTPHeaderRange,                 HTTPHeaderTypeRequest },
    { kHTTPHeaderReferer,               HTTPHeaderTypeRequest },
    { kHTTPHeaderTE,                    HTTPHeaderTypeRequest },
    { kHTTPHeaderDepth,                 HTTPHeaderTypeRequest },
    { kHTTPHeaderDestination,           HTTPHeaderTypeRequest },
    { kHTTPHeaderIf,                    HTTPHeaderTypeRequest },
    { kHTTPHeaderLockToken,             HTTPHeaderTypeRequest },
    { kHTTPHeaderOverwrite,             HTTPHeaderTypeRequest },
    { kHTTPHeaderTimeout,               HTTPHeaderTypeRequest },
    
    { kHTTPHeaderServer,                HTTPHeaderTypeResponse },
    { kHTTPHeaderSetCookie,             HTTPHeaderTypeResponse },
    { kHTTPHeaderAcceptRanges,          HTTPHeaderTypeResponse },
    { kHTTPHeaderWWWAuthenticate,       HTTPHeaderTypeResponse },
    { kHTTPHeaderAge,                   HTTPHeaderTypeResponse },
    { kHTTPHeaderETAG,                  HTTPHeaderTypeResponse },
    { kHTTPHeaderLocation,              HTTPHeaderTypeResponse },
    { kHTTPHeaderProxyAuthenticate,     HTTPHeaderTypeResponse },
    { kHTTPHeaderRetryAfter,            HTTPHeaderTypeResponse },
    { kHTTPHeaderTrailers,              HTTPHeaderTypeResponse },
    
    { kHTTPHeaderConnection,            HTTPHeaderTypeGeneral },
    { kHTTPHeaderCacheControl,          HTTPHeaderTypeGeneral },
    { kHTTPHeaderDate,                  HTTPHeaderTypeGeneral },
    { kHTTPHeaderTransferEncoding,      HTTPHeaderTypeGeneral },
    { kHTTPHeaderUpgrade,               HTTPHeaderTypeGeneral },
    { kHTTPHeaderVary,                  HTTPHeaderTypeGeneral },
    { kHTTPHeaderVia,                   HTTPHeaderTypeGeneral },
    { kHTTPHeaderWarning,               HTTPHeaderTypeGeneral },
    { kHTTPHeaderDAV,                   HTTPHeaderTypeGeneral },
    
    { kHTTPHeaderAllow,                 HTTPHeaderTypeEntity },
    { kHTTPHeaderContentEncoding,       HTTPHeaderTypeEntity },
    { kHTTPHeaderContentLanguage,       HTTPHeaderTypeEntity },
    { kHTTPHeaderContentLength,         HTTPHeaderTypeEntity },
    { kHTTPHeaderContentLocation,       HTTPHeaderTypeEntity },
    { kHTTPHeaderContentMD5,            HTTPHeaderTypeEntity },
    { kHTTPHeaderContentRange,          HTTPHeaderTypeEntity },
    { kHTTPHeaderContentType,           HTTPHeaderTypeEntity },
    { kHTTPHeaderExpires,               HTTPHeaderTypeEntity },
    { kHTTPHeaderLastModified,          HTTPHeaderTypeEntity },
    { kHTTPHeaderPragma,                HTTPHeaderTypeEntity },

    { nullptr,                          HTTPHeaderTypeNone },
};


/* header field tokens */

const char* kHTTPTokenClose =               "close";
const char* kHTTPTokenKeepalive =           "keep-alive";


/* http_constants */


http_constants::MapValueText http_constants::status_code_text;
http_constants::MapTextValue http_constants::version_text_code;
http_constants::MapValueText http_constants::version_code_text;
http_constants::MapTextValue http_constants::method_text_code;
http_constants::MapValueText http_constants::method_code_text;
http_constants::MapTextText  http_constants::header_text;

std::once_flag http_constants::constants_init;

void http_constants::init()
{
    std::call_once(constants_init, []()
    {
        for (auto status_ent = kHTTPStatusTable; status_ent->code != HTTPStatusCodeLast; status_ent++) {
            status_code_text.insert(PairValueText(status_ent->code, status_ent->text));
        }
        
        for (auto version_ent = kHTTPVersionTable; version_ent->version != HTTPVersionLast; version_ent++) {
            version_text_code.insert(PairTextValue(version_ent->text, version_ent->version));
            version_code_text.insert(PairValueText(version_ent->version, version_ent->text));
        }
        
        for (auto method_ent = kHTTPMethodTable; method_ent->method != HTTPMethodLast; method_ent++) {
            method_text_code.insert(PairTextValue(method_ent->text, method_ent->method));
            method_code_text.insert(PairValueText(method_ent->method, method_ent->text));
        }
        
        for (auto header_ent = kHTTPHeaderTable; header_ent->type != HTTPHeaderTypeNone; header_ent++) {
            header_text.insert(PairTextText(header_ent->text, header_ent->text));
        }
    });
}

const char* http_constants::get_status_text(int code)
{
    MapValueText::iterator mi = status_code_text.find(code);
#if USE_CPP_STRING_MAPS
    return (mi == status_code_text.end()) ? nullptr : (*mi).second.c_str();
#else
    return (mi == status_code_text.end()) ? nullptr : (*mi).second;
#endif
}

const HTTPVersion http_constants::get_version_type(const char* text)
{
    MapTextValue::iterator mi = version_text_code.find(text);
    return (mi == version_text_code.end()) ? HTTPVersionNone : (HTTPVersion)(*mi).second;
}

const char* http_constants::get_version_text(HTTPVersion version)
{
    MapValueText::iterator mi = version_code_text.find(version);
#if USE_CPP_STRING_MAPS
    return (mi == version_code_text.end()) ? nullptr : (*mi).second.c_str();
#else
    return (mi == version_code_text.end()) ? nullptr : (*mi).second;
#endif
}

const HTTPMethod http_constants::get_method_type(const char* text)
{
    MapTextValue::iterator mi = method_text_code.find(text);
    return (mi == method_text_code.end()) ? HTTPMethodNone : (HTTPMethod)(*mi).second;
}

const char* http_constants::get_method_text(HTTPMethod method)
{
    MapValueText::iterator mi = method_code_text.find(method);
#if USE_CPP_STRING_MAPS
    return (mi == method_code_text.end()) ? nullptr : (*mi).second.c_str();
#else
    return (mi == method_code_text.end()) ? nullptr : (*mi).second;
#endif
}

const char* http_constants::get_header_text(const char* text)
{
    MapTextText::iterator mi = header_text.find(text);
#if USE_CPP_STRING_MAPS
    return (mi == header_text.end()) ? nullptr : (*mi).second.c_str();
#else
    return (mi == header_text.end()) ? nullptr : (*mi).second;
#endif
}
